#!/usr/bin/bash
x86_64-w64-mingw32-g++ vmctx.S -I. -c -o vmctx.o
x86_64-w64-mingw32-g++ -static-libgcc -static-libstdc++ -DDEBUG main.cpp vmctx.o -I. -o rvm64.exe
clang++ test.cpp --target=riscv64 -march=rv64g -ffreestanding -nostdlib -fuse-ld=lld -isystem /usr/local/musl/include -Wl,-shared -Wl,-e,main -o test.elf
