#include <iostream>
#include <memory>
#include <string>
#include <cctype>
#include <map>
#include <fstream>
#include <sstream>

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/TargetSelect.h"

using namespace llvm;
using namespace llvm::orc;

static ExitOnError ExitOnErr;

// ----- CLI Configuration -----
struct Config {
    std::string input;
    std::string inputFile;
    bool emitLLVM = false;
    int optLevel = 0; // 0, 1, 2, 3
    bool interactive = true;
};

// ----- Lexer -----
enum Token {
    tok_eof = -1,
    tok_number = -2,
    tok_plus = '+',
    tok_minus = '-',
    tok_mul = '*',
    tok_div = '/',
};

static std::string NumStr;
static double NumVal;
static std::string Input;
static size_t Index = 0;

static int getNextToken() {
    while (Index < Input.size() && isspace(Input[Index])) ++Index;
    if (Index == Input.size()) return tok_eof;

    char ch = Input[Index];
    if (isdigit(ch) || ch == '.') {
        size_t len;
        NumVal = std::stod(Input.substr(Index), &len);
        Index += len;
        return tok_number;
    }

    ++Index;
    return ch;
}

// ----- Parser + AST -----
class ExprAST {
public:
    virtual ~ExprAST() = default;
    virtual Value* codegen(IRBuilder<>& builder) = 0;
};

class NumberExprAST : public ExprAST {
    double Val;
public:
    NumberExprAST(double val) : Val(val) {}
    Value* codegen(IRBuilder<>& builder) override {
        return ConstantFP::get(builder.getDoubleTy(), Val);
    }
};

class BinaryExprAST : public ExprAST {
    char Op;
    std::unique_ptr<ExprAST> LHS, RHS;
public:
    BinaryExprAST(char op, std::unique_ptr<ExprAST> lhs, std::unique_ptr<ExprAST> rhs)
        : Op(op), LHS(std::move(lhs)), RHS(std::move(rhs)) {}
    Value* codegen(IRBuilder<>& builder) override {
        Value* L = LHS->codegen(builder);
        Value* R = RHS->codegen(builder);
        switch (Op) {
            case '+': return builder.CreateFAdd(L, R, "addtmp");
            case '-': return builder.CreateFSub(L, R, "subtmp");
            case '*': return builder.CreateFMul(L, R, "multmp");
            case '/': return builder.CreateFDiv(L, R, "divtmp");
            default: return nullptr;
        }
    }
};

// ----- Recursive descent parser -----
static int CurTok;
static int getNext() { return CurTok = getNextToken(); }

std::unique_ptr<ExprAST> parsePrimary() {
    if (CurTok == tok_number) {
        auto result = std::make_unique<NumberExprAST>(NumVal);
        getNext();
        return result;
    }
    std::cerr << "Unknown token in primary\n";
    return nullptr;
}

std::unique_ptr<ExprAST> parseBinOpRHS(int exprPrec, std::unique_ptr<ExprAST> LHS);

int getTokPrecedence(char op) {
    switch (op) {
        case '+':
        case '-': return 10;
        case '*':
        case '/': return 20;
        default: return -1;
    }
}

std::unique_ptr<ExprAST> parseExpression() {
    auto LHS = parsePrimary();
    if (!LHS) return nullptr;
    return parseBinOpRHS(0, std::move(LHS));
}

std::unique_ptr<ExprAST> parseBinOpRHS(int exprPrec, std::unique_ptr<ExprAST> LHS) {
    while (true) {
        int tokPrec = getTokPrecedence(CurTok);
        if (tokPrec < exprPrec) return LHS;

        char BinOp = CurTok;
        getNext();

        auto RHS = parsePrimary();
        if (!RHS) return nullptr;

        int nextPrec = getTokPrecedence(CurTok);
        if (tokPrec < nextPrec)
            RHS = parseBinOpRHS(tokPrec + 1, std::move(RHS));

        LHS = std::make_unique<BinaryExprAST>(BinOp, std::move(LHS), std::move(RHS));
    }
}

// ----- Optimization -----
void optimizeModule(Module* M, int optLevel) {
    if (optLevel == 0) return;

    legacy::FunctionPassManager FPM(M);

    if (optLevel >= 1) {
        FPM.add(createInstructionCombiningPass());
        FPM.add(createReassociatePass());
    }
    if (optLevel >= 2) {
        FPM.add(createGVNPass());
        FPM.add(createCFGSimplificationPass());
    }
    if (optLevel >= 3) {
        FPM.add(createDeadCodeEliminationPass());
    }

    FPM.doInitialization();
    for (auto &F : *M)
        FPM.run(F);
}

// ----- Code generation -----
int processExpression(const std::string& expr, const Config& config) {
    Input = expr;
    Index = 0;
    getNext();

    auto AST = parseExpression();
    if (!AST) {
        std::cerr << "Failed to parse expression\n";
        return 1;
    }

    LLVMContext Context;
    IRBuilder<> Builder(Context);
    auto ModulePtr = std::make_unique<Module>("calc", Context);

    FunctionType *FT = FunctionType::get(Type::getDoubleTy(Context), false);
    Function *F = Function::Create(FT, Function::ExternalLinkage, "calc_expr", ModulePtr.get());
    BasicBlock *BB = BasicBlock::Create(Context, "entry", F);
    Builder.SetInsertPoint(BB);

    Value* RetVal = AST->codegen(Builder);
    Builder.CreateRet(RetVal);

    verifyFunction(*F);

    // Apply optimizations
    optimizeModule(ModulePtr.get(), config.optLevel);

    if (config.emitLLVM) {
        std::cout << "\n=== LLVM IR ===\n";
        ModulePtr->print(llvm::outs(), nullptr);
        std::cout << "===============\n\n";
    }

    // Execute with JIT
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();
    
    auto JIT = ExitOnErr(LLJITBuilder().create());
    ExitOnErr(JIT->addIRModule(ThreadSafeModule(std::move(ModulePtr), std::make_unique<LLVMContext>())));
    
    auto ResultAddr = ExitOnErr(JIT->lookup("calc_expr"));
    double (*FP)() = ResultAddr.toPtr<double(*)()>();
    double result = FP();
    
    std::cout << "Result: " << result << "\n";

    return 0;
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n"
              << "Options:\n"
              << "  -f <file>       Read expression from file\n"
              << "  -e <expr>       Evaluate expression from command line\n"
              << "  -emit-ir        Emit LLVM IR to stdout\n"
              << "  -O<level>       Set optimization level (0-3, default: 0)\n"
              << "  -h, --help      Show this help message\n"
              << "\nIf no options are provided, runs in interactive mode.\n";
}

Config parseArgs(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        } else if (arg == "-f") {
            if (i + 1 >= argc) {
                std::cerr << "Error: -f requires a filename\n";
                exit(1);
            }
            config.inputFile = argv[++i];
            config.interactive = false;
        } else if (arg == "-e") {
            if (i + 1 >= argc) {
                std::cerr << "Error: -e requires an expression\n";
                exit(1);
            }
            config.input = argv[++i];
            config.interactive = false;
        } else if (arg == "-emit-ir") {
            config.emitLLVM = true;
        } else if (arg.substr(0, 2) == "-O") {
            if (arg.length() > 2) {
                config.optLevel = arg[2] - '0';
                if (config.optLevel < 0 || config.optLevel > 3) {
                    std::cerr << "Error: Invalid optimization level. Use 0-3.\n";
                    exit(1);
                }
            } else {
                std::cerr << "Error: -O requires a level (0-3)\n";
                exit(1);
            }
        } else {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            printUsage(argv[0]);
            exit(1);
        }
    }
    
    return config;
}

int main(int argc, char* argv[]) {
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    
    Config config = parseArgs(argc, argv);

    if (config.interactive) {
        std::cout << "Enter expression: ";
        std::getline(std::cin, config.input);
        return processExpression(config.input, config);
    } else if (!config.inputFile.empty()) {
        std::ifstream file(config.inputFile);
        if (!file) {
            std::cerr << "Error: Cannot open file '" << config.inputFile << "'\n";
            return 1;
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        config.input = buffer.str();
        return processExpression(config.input, config);
    } else {
        return processExpression(config.input, config);
    }
}