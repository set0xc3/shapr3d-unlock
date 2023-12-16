const std = @import("std");

const win32 = std.os.windows;
const kernel32 = std.os.windows.kernel32;

pub const STANDARD_RIGHTS_REQUIRED: win32.DWORD = 0x000F0000;
pub const SYNCHRONIZE: win32.DWORD = 0x00100000;
pub const PROCESS_ALL_ACCESS: win32.DWORD = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;

pub const TH32CS_SNAPPROCESS: win32.DWORD = 0x00000002;

pub const PROCESS_VM_OPERATION: win32.DWORD = 0x0008;
pub const PROCESS_VM_WRITE: win32.DWORD = 0x0008;

pub const PROCESSENTRY32W = struct {
    dwSize: win32.DWORD,
    cntUsage: win32.DWORD,
    th32ProcessID: win32.DWORD,
    th32DefaultHeapID: win32.ULONG_PTR,
    th32ModuleID: win32.DWORD,
    cntThreads: win32.DWORD,
    th32ParentProcessID: win32.DWORD,
    pcPriClassBase: win32.LONG,
    dwFlags: win32.DWORD,
    szExeFile: [win32.MAX_PATH]win32.WCHAR,
};

const LPPROCESSENTRY32 = *PROCESSENTRY32W;

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: win32.DWORD,
    bInheritHandle: win32.BOOL,
    dwProcessId: win32.DWORD,
) callconv(win32.WINAPI) win32.HANDLE;

pub extern "kernel32" fn Process32FirstW(
    hSnapshot: win32.HANDLE,
    lppe: LPPROCESSENTRY32,
) callconv(win32.WINAPI) win32.BOOL;

pub extern "kernel32" fn Process32NextW(
    hSnapshot: win32.HANDLE,
    lppe: LPPROCESSENTRY32,
) callconv(win32.WINAPI) win32.BOOL;

pub extern "kernel32" fn GetPriorityClass(
    hProcess: win32.HANDLE,
) callconv(win32.WINAPI) win32.DWORD;

pub extern "user32" fn FindWindowA(
    lpClassName: ?win32.LPCSTR,
    lpWindowName: ?win32.LPCSTR,
) callconv(win32.WINAPI) ?win32.HWND;

pub extern "user32" fn GetWindowThreadProcessId(
    hWnd: ?win32.HWND,
    lpdwProcessId: *win32.DWORD,
) callconv(win32.WINAPI) win32.DWORD;

pub fn GetModuleBaseAddress(lpszModuleName: [*]const u8, pID: win32.DWORD) ?*win32.BYTE {
    _ = lpszModuleName;
    const hSnap: win32.HANDLE = kernel32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPALL, pID);
    defer win32.CloseHandle(hSnap);
    if (hSnap != win32.INVALID_HANDLE_VALUE) {
        var modEntry: win32.MODULEENTRY32 = undefined;
        modEntry.dwSize = @sizeOf(win32.MODULEENTRY32);
        if (kernel32.Module32First(hSnap, &modEntry) == win32.FALSE) {
            return null;
        }

        while (true) {
            // std.debug.print("process_handle: {s}\n", .{modEntry.szModule[0..13]});

            if (std.mem.eql(u8, modEntry.szModule, "mimeTools.dll")) {
                std.debug.print("modEntry.th32ProcessID: {}\n", .{modEntry.modBaseAddr});
                return modEntry.modBaseAddr;
            }
            if (kernel32.Module32Next(hSnap, &modEntry) == win32.FALSE) {
                return null;
            }
        }
    }

    return null;
}

pub fn GetProcessIdFromListBytName(process_name: []const u8) win32.DWORD {
    var hProcessSnap: win32.HANDLE = undefined;
    var hProcess: win32.HANDLE = undefined;
    var pe32: PROCESSENTRY32W = undefined;
    var dwPriorityClass: win32.DWORD = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == win32.INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = @sizeOf(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnap, &pe32) == win32.FALSE) {
        win32.CloseHandle(hProcessSnap);
        return 0;
    }

    if (Process32FirstW(hProcessSnap, &pe32) == win32.FALSE) {
        return 0;
    }

    while (true) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, win32.FALSE, pe32.th32ProcessID);
        if (hProcess != null) {
            dwPriorityClass = GetPriorityClass(hProcess);
            if (!dwPriorityClass) {
                win32.CloseHandle(hProcess);
                continue;
            }
        }

        if (std.mem.eql(u8, pe32.szExeFile, process_name)) {
            return pe32.th32ProcessID;
        }

        if (Process32NextW(hProcessSnap, &pe32) == win32.FALSE) {
            return 0;
        }
    }

    win32.CloseHandle(hProcessSnap);
    return 0;
}

pub fn GetWindowHandleByTitle(window_title: win32.LPCSTR) win32.HWND {
    const window_handle: win32.HWND = FindWindowA(null, window_title);
    return window_handle;
}

pub fn GetWindowHandleByClass(class_name: win32.LPCSTR) win32.HWND {
    const window_handle: win32.HWND = FindWindowA(class_name, null);
    return window_handle;
}

pub fn GetProcessIdFromWindowHandle(window_handle: win32.HWND) win32.DWORD {
    var process_id: win32.DWORD = 0;
    GetWindowThreadProcessId(window_handle, &process_id); // get the process id using window handle
    return process_id;
}

pub fn GetProcessIdByTitle(window_title: win32.LPCSTR) win32.DWORD {
    return GetProcessIdFromWindowHandle(GetWindowHandleByTitle(window_title));
}
pub fn GetProcessIdByClass(class_name: win32.LPCSTR) win32.DWORD {
    return GetProcessIdFromWindowHandle(GetWindowHandleByClass(class_name));
}

pub fn GetProcessHandleByProcessId(process_id: win32.DWORD, desired_access: win32.DWORD) win32.HANDLE {
    return OpenProcess(desired_access, win32.FALSE, process_id);
}

pub fn GetProcessHandleByTitle(window_title: win32.LPCSTR, desired_access: win32.DWORD) win32.HANDLE {
    return GetProcessHandleByProcessId(GetProcessIdByTitle(window_title), desired_access);
}

pub fn GetProcessHandleByClass(class_name: win32.LPCSTR, desired_access: win32.DWORD) win32.HANDLE {
    return GetProcessHandleByProcessId(GetProcessIdByClass(class_name), desired_access);
}

pub fn WriteByte(pHandle: win32.HANDLE, address: u32, byte: u32, size: u32) bool {
    var bytesRead: u64 = 0;
    _ = win32.WriteProcessMemory(pHandle, address, &byte, size, &bytesRead);
    return bytesRead == size;
}

pub fn main() void {
    const process_id = GetProcessIdFromListBytName("Shapr3D.exe");
    if (process_id == 0) {
        return;
    }

    const pHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, win32.FALSE, process_id);
    if (pHandle == null) {
        return;
    }
}
