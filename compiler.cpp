#include <iostream>
#include <memory>
#include <string>
#include <cctype>
#include <map>

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"

using namespace llvm;
using namespace llvm::orc;

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

// ----- Code generation -----
int main() {
    std::cout << "Enter expression: ";
    std::getline(std::cin, Input);
    Index = 0;
    getNext();

    auto AST = parseExpression();
    if (!AST) return 1;

    LLVMContext Context;
    IRBuilder<> Builder(Context);
    auto ModulePtr = std::make_unique<Module>("calc", Context);

    FunctionType *FT = FunctionType::get(Type::getDoubleTy(Context), false);
    Function *F = Function::Create(FT, Function::ExternalLinkage, "main", ModulePtr.get());
    BasicBlock *BB = BasicBlock::Create(Context, "entry", F);
    Builder.SetInsertPoint(BB);

    Value* RetVal = AST->codegen(Builder);
    Builder.CreateRet(RetVal);

    verifyFunction(*F);
    ModulePtr->print(llvm::errs(), nullptr);

    return 0;
}

