llc -filetype=obj main.ll -o main.o
clang -c capstone.c -I/opt/homebrew/include -o capstone.o
clang main.o capstone.o -L/opt/homebrew/lib -lcapstone -o test_capstone
