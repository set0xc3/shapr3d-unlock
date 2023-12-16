#include <windows.h>
#include <TlHelp32.h>

#include <stdio.h>
#include <iostream>
#include <cmath>
#include <vector>

#include "mem.h"
#include "mem.cpp"

int main(void) {
    DWORD process_id = MEM::GetProcessIdFromListBytName("Shapr3D_Beta.exe");
    if (process_id == 0) {
        return 0;
    }

    HANDLE pHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_id);
    if (pHandle == 0) {
        return 0;
    }

    // get base address
    char module_name[] = "Shapr3D_Beta.dll";
    uintptr_t shapr3d = MEM::GetModuleBaseAddress(_T(module_name), process_id);
    printf("(0x%llX) GetModuleBaseAddress: 0x%llX\n", (uintptr_t)pHandle, shapr3d);

    if (!MEM::WriteByte(pHandle, shapr3d + 0x1B791F6, 0x9090C18B48, 5)) {
        printf("Failed WriteByte\n");
    }
    printf("(0x%llX) WriteProcessMemory: 0x%llX\n", (uintptr_t)pHandle, shapr3d);

    return 0;
}