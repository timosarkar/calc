clang++ compiler.cpp -std=c++20 -g \
  `llvm-config --cxxflags` \
  `llvm-config --ldflags --system-libs --libs core support orcjit native` \
  -o calculator