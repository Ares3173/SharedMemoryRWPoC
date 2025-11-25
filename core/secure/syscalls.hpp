#ifndef SYSCALLS_HPP
#define SYSCALLS_HPP

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemExtendedHandleInformation = 0x40
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* NtQueryInformationThread)(HANDLE hThread, THREADINFOCLASS TIC, void* pBuffer, ULONG BufferSize, ULONG* SizeOut);
typedef NTSTATUS(NTAPI* NtCreateProcessStateChange)(PHANDLE StateChangeHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, ULONG Unknown);
typedef NTSTATUS(NTAPI* NtChangeProcessState)(HANDLE StateChangeHandle, HANDLE ProcessHandle, ULONG Action, PVOID ExtendedInformation, SIZE_T ExtendedInformationLength, ULONG64 Reserved);
typedef NTSTATUS(NTAPI* NtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* NtAdjustPrivilegesToken)(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtCreateSection)(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* RegionSize, ULONG FreeType);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI* NtClose)(HANDLE Handle);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtSetInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS(NTAPI* NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS(NTAPI* NtSetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS(NTAPI* NtCreateJobObject)(PHANDLE hJobHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* pObjectAttributes);
typedef NTSTATUS(NTAPI* NtSetInformationJobObject)(HANDLE hJobHandle, ntenum::JOBOBJECTINFOCLASS2 InfoClass, void* pInfo, ULONG InfoLen);
typedef NTSTATUS(NTAPI* NtAssignProcessToJobObject)(HANDLE JobHandle, HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern "C"
{
	NTSTATUS NTAPI AllSyscallStub();
}

namespace secure
{
	namespace syscalls
	{
		int GetSsnByName(PCHAR syscall);

		template<typename Functor, typename... Args>
		__forceinline NTSTATUS doSyscall(const char* syscall, Args&&... args)
		{
			DWORD SyscallNum = GetSsnByName((PCHAR)syscall);
			if (SyscallNum)
			{
				__writegsdword(0x16B4, SyscallNum);
				return (reinterpret_cast<Functor>(AllSyscallStub))(std::forward<Args>(args)...);
			}
			return -1;
		}
	}
}

#endif