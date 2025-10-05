clang++ a.cpp -std=c++20 -g \                ~/projects/a
  `llvm-config --cxxflags --ldflags --system-libs --libs all` \
  -o calculator
