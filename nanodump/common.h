#pragma once
#include <Windows.h>
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

#define ADVAPI32_DLL L"Advapi32.dll"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
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

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}

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

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

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


HANDLE obtain_lsass_handle(DWORD pid, DWORD permissions, BOOL dup, BOOL fork, BOOL is_malseclogon_stage_2, LPCSTR dump_path);
HANDLE duplicate_lsass_handle(DWORD lsass_pid, DWORD permissions);
HANDLE get_process_handle(DWORD dwPid, DWORD dwFlags, BOOL quiet);
HANDLE fork_process(DWORD dwPid, HANDLE hProcess);
HANDLE find_lsass(DWORD dwFlags);
HANDLE make_handle_full_access(HANDLE hProcess);
PSYSTEM_HANDLE_INFORMATION get_all_handles();

HANDLE get_function_address(HMODULE hLibrary, DWORD FunctionHash, WORD Ordinal);
HANDLE get_library_address(LPWSTR LibName, BOOL DoLoad);

PVOID allocate_memory(PSIZE_T region_size);
void free_linked_list(PVOID head);
BOOL is_full_path(LPCSTR filename);
LPCWSTR get_cwd(VOID);
VOID get_full_path(PUNICODE_STRING full_dump_path, LPCSTR filename);
BOOL create_file(PUNICODE_STRING full_dump_path);
BOOL delete_file(LPCSTR filepath);
BOOL file_exists(LPCSTR filepath);
BOOL write_file(PUNICODE_STRING full_dump_path, PBYTE fileData, ULONG32 fileLength);
void generate_invalid_sig(PULONG32 Signature, PSHORT Version, PSHORT ImplementationVersion);
void print_success(LPCSTR dump_path, BOOL use_valid_sig, BOOL write_dump_to_disk);

#if defined(NANO) && !defined(SSP)
PVOID get_process_image(HANDLE hProcess);
BOOL is_lsass(HANDLE hProcess);
DWORD get_pid(HANDLE hProcess);
DWORD get_lsass_pid(void);
BOOL kill_process(DWORD pid);
BOOL wait_for_process(HANDLE hProcess);
#endif