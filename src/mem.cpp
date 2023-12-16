#include "mem.h"

#include <stdio.h>

namespace MEM {
    HWND GetWindowHandleByTitle(LPCSTR window_title) {
        HWND window_handle = FindWindowA(nullptr, window_title);
        return window_handle;
    }

    HWND GetWindowHandleByClass(LPCSTR class_name) {
        HWND window_handle = FindWindowA(class_name, nullptr);
        return window_handle;
    }

    DWORD GetProcessIdFromWindowHandle(HWND window_handle) {
        DWORD process_id;
        GetWindowThreadProcessId(window_handle, &process_id); // get the process id using window handle
        return process_id;
    }

    DWORD GetProcessIdByTitle(LPCSTR window_title) {
        return GetProcessIdFromWindowHandle(GetWindowHandleByTitle(window_title));
    }

    DWORD GetProcessIdByClass(LPCSTR class_name) {
        return GetProcessIdFromWindowHandle(GetWindowHandleByClass(class_name));
    }

    DWORD GetProcessIdFromListBytName(const char* process_name) {
        HANDLE hProcessSnap;
        HANDLE hProcess;
        PROCESSENTRY32 pe32;
        DWORD dwPriorityClass;

        // Take a snapshot of all processes in the system.
        hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if( hProcessSnap == INVALID_HANDLE_VALUE )
        {
            return 0;
        }

        // Set the size of the structure before using it.
        pe32.dwSize = sizeof( PROCESSENTRY32 );

        // Retrieve information about the first process,
        // and exit if unsuccessful
        if( !Process32First( hProcessSnap, &pe32 ) )
        {
            CloseHandle( hProcessSnap );          // clean the snapshot object
            return 0;
        }

        // Now walk the snapshot of processes, and
        // display information about each process in turn
        do
        {
            // Retrieve the priority class.
            dwPriorityClass = 0;
            hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
            if( hProcess == NULL )
            {

            }
            else
            {
                dwPriorityClass = GetPriorityClass( hProcess );
                if( !dwPriorityClass )
                CloseHandle( hProcess );
            }

            if (_tcscmp(pe32.szExeFile, _T(process_name)) == 0) {
                return pe32.th32ProcessID;
                break;
            }

        } while( Process32Next( hProcessSnap, &pe32 ) );

        CloseHandle( hProcessSnap );
        return 0;
    }

    HANDLE GetProcessHandleByProcessId(DWORD process_id, DWORD desired_access) {
        return OpenProcess(desired_access, FALSE, process_id);
    }

    HANDLE GetProcessHandleByTitle(LPCSTR window_title, DWORD desired_access) {
        return GetProcessHandleByProcessId(GetProcessIdByTitle(window_title), desired_access);
    }

    HANDLE GetProcessHandleByClass(LPCSTR class_name, DWORD desired_access) {
        return GetProcessHandleByProcessId(GetProcessIdByClass(class_name), desired_access);
    }

    uintptr_t GetModuleBaseAddress(TCHAR *modName, DWORD processId) {

        uintptr_t base_address = 0;

        // takes snapshot of all loaded modules in process
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

        // check if snapshot is valid
        if (hSnap != INVALID_HANDLE_VALUE) {

            // create struct that holds the module info while iterating
            MODULEENTRY32 moduleEntry;
            moduleEntry.dwSize = sizeof(moduleEntry);

            // if a module exists in snapshot, get entry
            if (Module32First(hSnap, &moduleEntry)) { // select first entry
                do {
                    if (_tcscmp(moduleEntry.szModule, modName) == 0) {
                        base_address = (uintptr_t) moduleEntry.modBaseAddr;
                        printf("%s : %s\n", modName, moduleEntry.szModule);
                        break;
                    }
                } while (Module32Next(hSnap, &moduleEntry)); // select next module
            }
        }

        CloseHandle(hSnap);
        return base_address;
    }

    int ReadInt(HANDLE pHandle, uintptr_t address) {
        int buffer;
        ReadProcessMemory(pHandle, (LPCVOID) address, &buffer, sizeof(int), nullptr);
        return buffer;
    }

    double ReadDouble(HANDLE pHandle, uintptr_t address) {
        double buffer;
        ReadProcessMemory(pHandle, (LPCVOID) address, &buffer, sizeof(double), nullptr);
        return buffer;
    }

    float ReadFloat(HANDLE pHandle, uintptr_t address) {
        float buffer;
        ReadProcessMemory(pHandle, (LPCVOID) address, &buffer, sizeof(float), nullptr);
        return buffer;
    }

    BOOL WriteByte(HANDLE pHandle, uintptr_t address, uintptr_t byte, size_t size) {
        DWORD old_protect;
        VirtualProtectEx(pHandle, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &old_protect);

        size_t bytesRead;
        BOOL ok = WriteProcessMemory((LPVOID)pHandle, (LPVOID)address, (LPCVOID)&byte, size, &bytesRead);
        if (ok && bytesRead == size) {
            printf("OK: (0x%llX) WriteProcessMemory: 0x%llX - 0x%llX:%zu\n", (uintptr_t)pHandle, address, byte, size);
        } else {
            printf("FAILED: (0x%llX) WriteProcessMemory: 0x%llX - 0x%llX:%zu\n", (uintptr_t)pHandle, address, byte, size);
        }
        printf("WriteByte: %zu\n", bytesRead);

        VirtualProtectEx(pHandle, (LPVOID)address, size, old_protect, &old_protect);

        return bytesRead == size;
    }

    void WriteInt(HANDLE pHandle, uintptr_t address, int value) {
        WriteProcessMemory(pHandle, (LPVOID) address, &value, sizeof(int), nullptr);
    }

    void WriteDouble(HANDLE pHandle, uintptr_t address, double value) {
        WriteProcessMemory(pHandle, (LPVOID) address, &value, sizeof(double), nullptr);
    }

    void WriteFloat(HANDLE pHandle, uintptr_t address, float value) {
        WriteProcessMemory(pHandle, (LPVOID) address, &value, sizeof(float), nullptr);
    }

    LPCVOID AddressToPointerC(uintptr_t address) {
        return (LPCVOID) address;
    }

    LPVOID AddressToPointer(uintptr_t address) {
        return (LPVOID) address;
    }
}