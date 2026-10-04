ProcessHollowing
=================

This repository contains a C++ program (ProcessHollowing.cpp) that implements the core steps used in a process hollowing technique. The README below describes only what is present in the source file — no additional features or behaviors are assumed.

What the program does
- Creates a new process in a suspended state using CreateProcessA.
- Opens a user-supplied file (expected to be a PE executable) and obtains its size.
- Allocates memory in the loader process and reads the file contents into that buffer.
- Validates the file as a PE by checking the DOS header (e_magic == "MZ").
- Locates the IMAGE_NT_HEADERS using the DOS header's e_lfanew field.
- Prints some diagnostic information and pauses for user input at several points.
- Obtains the target thread CONTEXT (ContextFlags = CONTEXT_INTEGER) via GetThreadContext.
- Checks PE OptionalHeader.Magic to compare target/loader bitness (PE32 vs PE32+).
- Reads the target process PEB (via RDX on x64, EBX on x86) and reads the ImageBaseAddress with ReadProcessMemory.
- Inspects the base relocation directory (IMAGE_DIRECTORY_ENTRY_BASERELOC) and obtains the address of NtUnmapViewOfSection from ntdll.dll (GetProcAddress).

Usage
- The program expects two command-line arguments:
  1) target process command line (the process to create in suspended state)
  2) path to the PE file to be injected

Example (syntax):
  process_hollowing.exe "C:\Path\to\target.exe" "C:\Path\to\payload.exe"

Build
- Build with Microsoft Visual Studio on Windows as a native console application.
- The source includes Windows headers and uses Windows APIs (CreateProcessA, ReadFile, VirtualAlloc, GetThreadContext, ReadProcessMemory, etc.).
- Compile for the architecture you intend to target (the source contains conditional code paths for x64 vs x86).

Notes
- This README describes only what is implemented and visible in ProcessHollowing.cpp. It does not document any runtime behavior beyond the source logic and diagnostic output present in the file.
