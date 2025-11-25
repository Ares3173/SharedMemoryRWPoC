#include "../pch.h"
#include "memory.h"

namespace memory
{
	bool section::create()
	{
		errCode = secure::syscalls::doSyscall<NtCreateSection>(
			"NtCreateSection",
			handle.getAddress(),
			SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
			nullptr,
			reinterpret_cast<PLARGE_INTEGER>(&sz),
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			nullptr
		);
		if (NT_FAIL(errCode))
			return false;
		TRACE("Created Section of Sz {}", sz);
		return true;
	}

	bool section::mapView(HANDLE Proc, DWORD Permissions)
	{
		const auto Addr = (Proc == NtCurrentProcess()) ? &localAddr : &remoteAddr;
		errCode = secure::syscalls::doSyscall<NtMapViewOfSection>("NtMapViewOfSection", (HANDLE)handle, Proc, Addr, NULL, NULL, nullptr, &sz, 2, NULL, Permissions);
		if (NT_FAIL(errCode))
			return false;
		TRACE("Mapped View of Section for Handle {} of Sz {} On Process {} @ {}", fmt::ptr((HANDLE)handle), sz, fmt::ptr(Proc), fmt::ptr(*Addr));
		return true;
	}

	bool section::unMapView(HANDLE Proc)
	{
		const auto Addr = (Proc == NtCurrentProcess()) ? &localAddr : &remoteAddr;
		errCode = secure::syscalls::doSyscall<NtUnmapViewOfSection>("NtUnmapViewOfSection", Proc, Addr);
		if (NT_FAIL(errCode))
			return false;
		TRACE("Unmapped View of Section for Handle {} of Sz {} On Process {} @ {}", fmt::ptr((HANDLE)handle), sz, fmt::ptr(Proc), fmt::ptr(Addr));
		return true;
	}

	PVOID section::getRemoteAddr()
	{
		return remoteAddr;
	}
	PVOID section::getLocalAddr()
	{
		return localAddr;
	}

	void section::setRemoteAddr(void* set)
	{
		remoteAddr = set;
	}

	NTSTATUS section::getErr()
	{
		return errCode;
	}

	std::size_t section::getSz()
	{
		return sz;
	}

	void section::free()
	{
		unMapView(NtCurrentProcess());
		DEBUG("[Free'd] Section: {}", fmt::ptr(localAddr));
	}

}