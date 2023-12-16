@echo off

clang++ src/main.cpp -O0 -g -lkernel32 -luser32 -ladvapi32 -o shapr3d_hack-debug.exe