#pragma once
#include "defsWin10.h"
#include "defsWin11.h"

#define NTAPI __stdcall

#define DEF_STRUCT_DEFAULT(name, suffix)	\
using name		= name##suffix;				\
using P##name	= P##name##suffix;			\
using _##name	= _##name##suffix;

#define DEF_STRUCT_DEFAULT_32(name, suffix)	\
using name##_32		= name##suffix##_32;	\
using P##name##_32	= P##name##suffix##_32;	\
using _##name##_32	= _##name##suffix##_32;

#ifndef _WIN32_WINNT
#error Not supported
#else
#if(_WIN32_WINNT == _WIN32_WINNT_WIN7)
DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN7)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN7)

#ifdef _WIN64
DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN7)
DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN7)
#endif
#elif (_WIN32_WINNT == _WIN32_WINNT_WIN8)
DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN8)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN8)

#ifdef _WIN64
DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN8)
DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN8)
#endif
#elif (_WIN32_WINNT == _WIN32_WINNT_WINBLUE)
DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN81)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN81)

#ifdef _WIN64
DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN81)
DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN81)
#endif
#elif (_WIN32_WINNT == _WIN32_WINNT_WIN10) //includes Win11
#if (WDK_NTDDI_VERSION == NTDDI_WIN10_CO) //Win11 SDK is called NTDDI_WIN10_CO
DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN11)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN11)

#ifdef _WIN64
DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN11)
DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN11)
#endif
#else
DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN10)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN10)

#ifdef _WIN64
DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN10)
DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN10)
#endif
#endif
#else
#error Not supported
#endif
#endif



using f_RtlRestoreContext = VOID(__cdecl*)(PCONTEXT ContextRecord, _EXCEPTION_RECORD* ExceptionRecord);

using f_NtQueryInformationProcess = NTSTATUS(__stdcall*)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

using f_RtlAnsiStringToUnicodeString = NTSTATUS(__stdcall*)
(
	UNICODE_STRING* DestinationString,
	const ANSI_STRING* SourceString,
	BOOLEAN					AllocateDestinationString
	);

typedef NTSTATUS(NTAPI* f_NtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	CLIENT_ID* ClientId
	);

typedef NTSTATUS(NTAPI* f_NtQueryVirtualMemory)(HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength);

typedef NTSTATUS(NTAPI* f_NtProtectVirtualMemory)(
	HANDLE               ProcessHandle,
	PVOID* BaseAddress,
	PULONG           NumberOfBytesToProtect,
	ULONG                NewAccessProtection,
	PULONG              OldAccessProtection);

typedef NTSTATUS(NTAPI* f_NtAllocateVirtualMemory) (
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

//NtSetInformationWorkerFactory
using f_NtSetInformationWorkerFactory = NTSTATUS(__stdcall*)
(
	__in HANDLE WorkerFactoryHandle,
	__in WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	__in_bcount(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
	__in ULONG WorkerFactoryInformationLength
	);

using f_NtFreeVirtualMemory = NTSTATUS(__stdcall*)
(
	HANDLE		ProcessHandle,
	PVOID* BaseAddress,
	SIZE_T* RegionSize,
	ULONG		FreeType
	);

using f_NtQueryObject = NTSTATUS(__stdcall*)
(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
	);

//NtWorkerFactoryWorkerReady

using f_NtWorkerFactoryWorkerReady = NTSTATUS(__stdcall*)
(
	HANDLE                   Handle
	);

using f_LdrpHandleTlsData = NTSTATUS(__fastcall*)
(
	LDR_DATA_TABLE_ENTRY* pEntry
	);

using f_NtQueryInformationWorkerFactory = NTSTATUS(__stdcall*)
(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	_In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
	_In_ ULONG WorkerFactoryInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

using f_LdrGetProcedureAddress = NTSTATUS(__stdcall*)
(
	PVOID				BaseAddress,
	ANSI_STRING* Name,
	ULONG				Ordinal,
	PVOID* ProcedureAddress
	);

using f_NtOpenSection = NTSTATUS(__stdcall*)
(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes
	);

using f_NtOpenFile = NTSTATUS(__stdcall*)
(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);

using f_NtCreateThreadEx = NTSTATUS(__stdcall*)
(
	HANDLE* pHandle,
	ACCESS_MASK		DesiredAccess,
	void* pAttr,
	HANDLE			hTargetProc,
	void* pFunc,
	void* pArg,
	ULONG			Flags,
	SIZE_T			ZeroBits,
	SIZE_T			StackSize,
	SIZE_T			MaxStackSize,
	void* pAttrListOut
	);

using f_RtlAllocateHeap = PVOID(__stdcall*)
(
	void* HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
	);

using f_RtlFreeHeap = BOOLEAN(__stdcall*)
(
	void*	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
	);

using f_memmove = VOID(__cdecl*)
(
	PVOID	UNALIGNED	Destination,
	LPCVOID	UNALIGNED	Source,
	SIZE_T				Length
	);

using f_RtlZeroMemory = VOID(__stdcall*)
(
	PVOID	UNALIGNED	Destination,
	SIZE_T				Length
	);

using f_NtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using f_NtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using f_NtUnmapViewOfSection = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(NTAPI* f_NtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);


//RtlDosApplyFileIsolationRedirection_Ustr
typedef NTSTATUS(NTAPI* f_RtlDosApplyFileIsolationRedirection_Ustr)(
	ULONG Flags,
	PUNICODE_STRING OriginalName,
	PUNICODE_STRING Extension,
	PUNICODE_STRING StaticString,
	PUNICODE_STRING DynamicString,
	PUNICODE_STRING* NewName,
	PULONG NewFlags,
	PSIZE_T FileNameSize,
	PSIZE_T RequiredLength
	);

typedef NTSTATUS(NTAPI* f_NtSuspendProcess)(
	HANDLE ProcessHandle
	);

typedef NTSTATUS(NTAPI* f_NtResumeProcess)(
	HANDLE ProcessHandle
	);

typedef VOID(NTAPI* f_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef VOID(NTAPI* f_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);