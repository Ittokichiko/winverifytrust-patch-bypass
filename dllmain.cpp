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
 
HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcId("Roblox"));
 
HMODULE module = LoadLibraryA("wintrust.dll");
 
FARPROC func = GetProcAddress(module, "WinVerifyTrust");
 
std::vector<BYTE> orig(6), hook = { 0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1 }; // sigma byte

int main() {
 
    ModifyFunc(process, func, hook, orig);
 
    HMODULE dll = LoadLibraryExA("urdll.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES); // your dll
    if (!dll) return EXIT_FAILURE;
 
    FARPROC Callback = GetProcAddress(dll, "urcallback"); // your dll's callback
    if (!Callback) return EXIT_FAILURE;
 
    DWORD tid = GetWindowThreadProcessId(FindWindowA(nullptr, "Roblox"), nullptr);
    HHOOK HookHandle = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)Callback, dll, tid);
    if (!HookHandle) return EXIT_FAILURE;
 
    PostThreadMessageA(tid, WM_NULL, 0, 0);
    std::cin.get();
 
    UnhookWindowsHookEx(HookHandle);
    WriteProcessMemory(process, func, orig.data(), orig.size(), nullptr);
    return EXIT_SUCCESS;
 
}
