#include <windows.h>
#include <vector>
#include <thread>
#include <iostream>
 
void ModifyFunc(HANDLE process, LPVOID addr, const std::vector<BYTE>& newBytes, std::vector<BYTE>& origBytes) {
    WriteProcessMemory(process, addr, newBytes.data(), newBytes.size(), nullptr);
}
 
DWORD GetProcId(const char* title) {
    HWND hwnd;
    while (!(hwnd = FindWindowA(nullptr, title))) std::this_thread::sleep_for(std::chrono::seconds(1));
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

int main() {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcId("FC24"));
    HMODULE modulewintrust = LoadLibraryA("wintrust.dll");
    FARPROC func = GetProcAddress(modulewintrust, "WinVerifyTrust");
    std::vector<BYTE> orig(6), hook = { 0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1 }; // sigma byte
    ModifyFunc(process, func, hook, orig);
    DWORD tid = GetWindowThreadProcessId(FindWindowA(nullptr, "FC24"), nullptr);
    HHOOK HookHandle = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)Callback, dll, tid);
    if (!HookHandle) return EXIT_FAILURE;
    PostThreadMessageA(tid, WM_NULL, 0, 0);
    UnhookWindowsHookEx(HookHandle);
    WriteProcessMemory(process, func, orig.data(), orig.size(), nullptr);
    return EXIT_SUCCESS;
 
}
