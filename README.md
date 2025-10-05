# calc

simple calculator programming language running on LLVM-IR ORCv2JIT

```bash
Usage: ./calculator [options]
Options:
  -f <file>       Read expression from file
  -e <expr>       Evaluate expression from command line
  -emit-ir        Emit LLVM IR to stdout
  -O<level>       Set optimization level (0-3, default: 0)
  -h, --help      Show this help message

If no options are provided, runs in interactive mode.
```

sample can be run using:

```bash
./calculator -f examples/sample.calc
```

### todo

- Multi-Pass into MLIR and then lowering into LLVM-IR
- PLO using LLVM BOLT
