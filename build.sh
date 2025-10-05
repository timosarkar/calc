clang++ compiler.cpp -std=c++20 -g \
  `llvm-config --cxxflags` \
  `llvm-config --ldflags --system-libs --libs core support orcjit native nativecodegen aarch64 aarch64codegen` \
  -o calculator