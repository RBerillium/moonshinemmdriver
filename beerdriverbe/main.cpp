#include <ntifs.h>
#include <stdint.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <minwindef.h>
#include "skCrypter.h"


extern "C"
{
    NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
        IN PEPROCESS		Process
    );

    PPEB NTAPI PsGetProcessPeb(PEPROCESS);

    PVOID NTAPI RtlFindExportedRoutineByName(PVOID, PCCH);

    NTSTATUS NTAPI ZwQuerySystemInformation(INT, PVOID, ULONG, PULONG);

    NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

    NTSTATUS NTAPI ZwQueryInformationProcess(
        _In_      HANDLE           ProcessHandle,
        _In_      PROCESSINFOCLASS ProcessInformationClass,
        _Out_     PVOID            ProcessInformation,
        _In_      ULONG            ProcessInformationLength,
        _Out_opt_ PULONG           ReturnLength
    );
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


void* get_system_information(INT info_class)
{
    unsigned long size = 32; char buffer[32];

    ZwQuerySystemInformation(info_class, buffer, size, &size);

    void* info = ExAllocatePoolWithTag( NonPagedPool, size, 'dbfc');

    if (!info)
    {
        return nullptr;
    }

    if (!NT_SUCCESS(ZwQuerySystemInformation(info_class, info, size, &size)))
    {
        ExFreePoolWithTag(info, 'dbfc');

        return nullptr;
    }

    return info;
}
uint64_t get_kernel_module(const char* name)
{

    auto to_lower = [](char* string) -> char*
        {
            for (char* pointer = string; *pointer != '\0'; pointer++)
            {
                *pointer = (char)(short)tolower(*pointer);
            }

            return string;
        };

    PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(11);

    if (!info) { return NULL; }

    for (uint64_t i = 0; i < info->NumberOfModules; i++)
    {
        RTL_PROCESS_MODULE_INFORMATION& module_info = info->Modules[i];

        if ((strcmp( to_lower((char*)module_info.FullPathName + module_info.OffsetToFileName), name) == 0))
        {
            void* address = module_info.ImageBase;

            ExFreePoolWithTag(info, 'dbfc'); return (uint64_t)address;
        }
    }

    ExFreePoolWithTag(info, 'dbfc'); return NULL;
}
__int64(__fastcall* original_win32k)(__int64 a1, __int64 a2);

#define rva(ptr, size) ((DWORD64)ptr + size + *(LONG*)((DWORD64)ptr + (size - sizeof(LONG)))) // <-- use this

NTSTATUS driver_entry(uint64_t NtGdiEngPlgBlt, uint64_t NtUserDestroyPalmRejectionDelayZone, uint64_t NtUserCreatePalmRejectionDelayZone, uint64_t MmCopyVirtualMemory_off)
{


    //manual offsets setup 22h2 19045.5965
#ifdef MANUAL_OFFSETS
    uint64_t NtGdiEngPlgBlt = 0xAAA0;
    uint64_t NtUserCreatePalmRejectionDelayZone = 0x9084;
    uint64_t NtUserDestroyPalmRejectionDelayZone = 0x90B0;
    uint64_t MmCopyVirtualMemory_off = 0x5FF1D0; 
#endif
    //search for win32k module address
    auto win32k = skCrypt("win32k.sys");
    uint64_t win32_k_module = get_kernel_module(win32k);
    win32k.clear();
    //clear string for anti-debug

    auto win32k_function_address = win32_k_module + NtGdiEngPlgBlt;

    uint64_t win32k_data_address = rva(win32k_function_address + 0xA, 7);

    uint64_t NtUserDestroyPalmRejectionDelayZone_address = win32_k_module + NtUserDestroyPalmRejectionDelayZone;
    uint64_t NtUserDestroyPalmRejectionDelayZone_data_address = rva(NtUserDestroyPalmRejectionDelayZone_address + 0x4, 7);

    uint64_t NtUserCreatePalmRejectionDelayZone_addr = win32_k_module + NtUserCreatePalmRejectionDelayZone;
    uint64_t NtUserCreatePalmRejectionDelayZone_data_address = rva(NtUserCreatePalmRejectionDelayZone_addr + 0x4, 7);

    //uint64_t NtUserInjectDeviceInput_addr = win32_k_module + NtUserInjectDeviceInput;
    //uint64_t NtUserInjectDeviceInput_data_addr = rva(NtUserInjectDeviceInput_addr + 0x4, 7);

    auto ntoskrnl = skCrypt("ntoskrnl.exe");
    uint64_t ntoskrnl_module_address = get_kernel_module(ntoskrnl);
    ntoskrnl.clear();

    uint64_t mm_copy_virtual_memory_address = ntoskrnl_module_address + MmCopyVirtualMemory_off;

    *(void**)win32k_data_address = (void*)mm_copy_virtual_memory_address;
    *(void**)NtUserDestroyPalmRejectionDelayZone_data_address = (void*)PsLookupProcessByProcessId;
    *(void**)NtUserCreatePalmRejectionDelayZone_data_address = (void*)PsGetProcessSectionBaseAddress; //PsGetProcessSectionBaseAddress
    
	return STATUS_SUCCESS;
}