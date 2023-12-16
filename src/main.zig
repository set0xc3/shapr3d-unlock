const std = @import("std");

const windows = std.os.windows;
const kernel32 = std.os.windows.kernel32;

pub const STANDARD_RIGHTS_REQUIRED: windows.DWORD = 0x000F0000;
pub const SYNCHRONIZE: windows.DWORD = 0x00100000;
pub const PROCESS_ALL_ACCESS: windows.DWORD = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwProcessId: windows.DWORD,
) callconv(windows.WINAPI) windows.HANDLE;

pub extern "user32" fn FindWindowA(
    lpClassName: ?windows.LPCSTR,
    lpWindowName: ?windows.LPCSTR,
) callconv(windows.WINAPI) ?windows.HWND;

pub extern "user32" fn GetWindowThreadProcessId(
    hWnd: ?windows.HWND,
    lpdwProcessId: *windows.DWORD,
) callconv(windows.WINAPI) windows.DWORD;

pub fn GetModuleBaseAddress(lpszModuleName: [*]const u8, pID: windows.DWORD) ?*windows.BYTE {
    _ = lpszModuleName;
    const hSnap: windows.HANDLE = kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPALL, pID);
    defer windows.CloseHandle(hSnap);
    if (hSnap != windows.INVALID_HANDLE_VALUE) {
        var modEntry: windows.MODULEENTRY32 = undefined;
        modEntry.dwSize = @sizeOf(windows.MODULEENTRY32);
        if (kernel32.Module32First(hSnap, &modEntry) == windows.FALSE) {
            return null;
        }

        while (true) {
            // std.debug.print("process_handle: {s}\n", .{modEntry.szModule[0..13]});

            if (std.mem.eql(u8, modEntry.szModule[0..13], "mimeTools.dll")) {
                std.debug.print("modEntry.th32ProcessID: {}\n", .{modEntry.modBaseAddr});
                return modEntry.modBaseAddr;
            }
            if (kernel32.Module32Next(hSnap, &modEntry) == windows.FALSE) {
                return null;
            }
        }
    }

    return null;
}

pub fn GetWindowHandleByTitle(window_title: windows.LPCSTR) windows.HWND {
    const window_handle: windows.HWND = FindWindowA(null, window_title);
    return window_handle;
}

pub fn GetWindowHandleByClass(class_name: windows.LPCSTR) windows.HWND {
    const window_handle: windows.HWND = FindWindowA(class_name, null);
    return window_handle;
}

pub fn main() !void {}
