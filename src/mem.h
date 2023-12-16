#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <cstdint>

namespace MEM {
    // --- Application APIs ---
    HWND GetWindowHandleByTitle(LPCSTR window_title);
    HWND GetWindowHandleByClass(LPCSTR class_name);

    DWORD GetProcessIdFromWindowHandle(HWND window_handle);
    DWORD GetProcessIdByTitle(LPCSTR window_title);
    DWORD GetProcessIdByClass(const char* class_name);
    DWORD GetProcessIdFromListBytName(LPCSTR process_name);

    HANDLE GetProcessHandleByProcessId(DWORD process_id, DWORD desired_access);
    HANDLE GetProcessHandleByTitle(LPCSTR window_title, DWORD desired_access);
    HANDLE GetProcessHandleByClass(LPCSTR class_name, DWORD desired_access);

    uintptr_t GetModuleBaseAddress(TCHAR *modName, DWORD procId);

    int ReadInt(HANDLE pHandle, uintptr_t address);
    double ReadDouble(HANDLE pHandle, uintptr_t address);
    float ReadFloat(HANDLE pHandle, uintptr_t address);

    BOOL WriteByte(HANDLE pHandle, uintptr_t address, uintptr_t bytes, size_t size);
    void WriteInt(HANDLE pHandle, uintptr_t address, int value);
    void WriteDouble(HANDLE pHandle, uintptr_t address, double value);
    void WriteFloat(HANDLE pHandle, uintptr_t address, float value);

    // --- Utils ---
    LPCVOID AddressToPointerC(uintptr_t address);
    LPVOID AddressToPointer(uintptr_t address);
}