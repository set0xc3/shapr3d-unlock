@echo off

clang++ src/main.cpp -O3 -lkernel32 -luser32 -ladvapi32 -o shapr3d_hack-release.exe