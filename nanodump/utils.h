#pragma once
#include "common.h"

#define OBJ_CASE_INSENSITIVE            0x00000040L

#define FILE_OPEN                       0x00000001
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020


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