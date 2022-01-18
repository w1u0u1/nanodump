#pragma once
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "common.h"

#ifndef offsetof
 #define offsetof(a,b) ((ULONG_PTR)(&(((a*)(0))->b)))
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define CALLBACK_FILE       0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09

#define MEM_COMMIT 0x1000
//#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD 0x100

// 200 MiB
#define DUMP_MAX_SIZE 0xc800000
// 900 KiB
#define CHUNK_SIZE 0xe1000

#define SIZE_OF_HEADER 32
#define SIZE_OF_DIRECTORY 12
#ifdef _WIN64
 #define SIZE_OF_SYSTEM_INFO_STREAM 48
#else
 #define SIZE_OF_SYSTEM_INFO_STREAM 56
#endif
#define SIZE_OF_MINIDUMP_MODULE 108

enum StreamType
{
    SystemInfoStream = 7,
    ModuleListStream = 4,
    Memory64ListStream = 9,
};

enum ProcessorArchitecture
{
    AMD64 = 9,
    INTEL = 0,
};

enum MiniDumpType
{
    MiniDumpNormal = 0,
};

typedef struct _MiniDumpHeader
{
     ULONG32       Signature;
     SHORT         Version;
     SHORT         ImplementationVersion;
     ULONG32       NumberOfStreams;
     ULONG32       StreamDirectoryRva;
     ULONG32       CheckSum;
     ULONG32       Reserved;
     ULONG32       TimeDateStamp;
     ULONG32       Flags;
} MiniDumpHeader, *PMiniDumpHeader;

typedef struct _MiniDumpDirectory
{
     ULONG32       StreamType;
     ULONG32       DataSize;
     ULONG32       Rva;
} MiniDumpDirectory, *PMiniDumpDirectory;

typedef struct _dump_context
{
    HANDLE  hProcess;
    PVOID   BaseAddress;
    ULONG32 rva;
    SIZE_T  DumpMaxSize;
    ULONG32 Signature;
    SHORT   Version;
    SHORT   ImplementationVersion;
} dump_context, *Pdump_context;

typedef struct _MiniDumpSystemInfo
{
    SHORT ProcessorArchitecture;
    SHORT ProcessorLevel;
    SHORT ProcessorRevision;
    char    NumberOfProcessors;
    char    ProductType;
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    ULONG32 CSDVersionRva;
    SHORT SuiteMask;
    SHORT Reserved2;
#if _WIN64
        ULONG64 ProcessorFeatures1;
        ULONG64 ProcessorFeatures2;
#else
        ULONG32 VendorId1;
        ULONG32 VendorId2;
        ULONG32 VendorId3;
        ULONG32 VersionInformation;
        ULONG32 FeatureInformation;
        ULONG32 AMDExtendedCpuFeatures;
#endif
} MiniDumpSystemInfo, *PMiniDumpSystemInfo;

typedef struct _VsFixedFileInfo
{
    ULONG32 dwSignature;
    ULONG32 dwStrucVersion;
    ULONG32 dwFileVersionMS;
    ULONG32 dwFileVersionLS;
    ULONG32 dwProductVersionMS;
    ULONG32 dwProductVersionLS;
    ULONG32 dwFileFlagsMask;
    ULONG32 dwFileFlags;
    ULONG32 dwFileOS;
    ULONG32 dwFileType;
    ULONG32 dwFileSubtype;
    ULONG32 dwFileDateMS;
    ULONG32 dwFileDateLS;
} VsFixedFileInfo, *PVsFixedFileInfo;

typedef struct _MiniDumpLocationDescriptor
{
    ULONG32 DataSize;
    ULONG32 rva;
} MiniDumpLocationDescriptor, *PMiniDumpLocationDescriptor;

typedef struct _MiniDumpModule
{
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    VsFixedFileInfo VersionInfo;
    MiniDumpLocationDescriptor CvRecord;
    MiniDumpLocationDescriptor MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} MiniDumpModule, *PMiniDumpModule;

typedef struct _MiniDumpMemoryDescriptor64
{
    struct _MiniDumpMemoryDescriptor64* next;
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
    DWORD   State;
    DWORD   Protect;
    DWORD   Type;
} MiniDumpMemoryDescriptor64, *PMiniDumpMemoryDescriptor64;


BOOL NanoDumpWriteDump(Pdump_context dc);