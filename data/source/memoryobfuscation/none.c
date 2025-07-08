void memoryobfuscation(){
  HANDLE hFile;
  DWORD bytesWritten;
  const char* data = "{{PROCESS_SPAWN}}";
  DWORD dataLen = (DWORD)lstrlenA(data);  // Use ANSI version

  hFile = CreateFileA(
        "C:\\output.txt",             // File name
        GENERIC_WRITE,            // Write access
        0,                        // No sharing
        NULL,                     // Default security
        CREATE_ALWAYS,            // Overwrite if exists
        FILE_ATTRIBUTE_NORMAL,    // Normal file
        NULL                      // No template
  );

  if (hFile == INVALID_HANDLE_VALUE)
        return 1;

  WriteFile(hFile, data, dataLen, &bytesWritten, NULL);
  CloseHandle(hFile);

}
