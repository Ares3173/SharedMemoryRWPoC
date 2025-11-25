#pragma once

namespace memory
{
	class section
	{
		utils::safeHandle handle;
		std::size_t sz;
		PVOID localAddr;
		PVOID remoteAddr;
		NTSTATUS errCode;
	public:
		section(std::size_t Sz) : sz(Sz), localAddr(nullptr), remoteAddr(nullptr), handle(INVALID_HANDLE_VALUE), errCode(NULL) {};
		bool create();
		bool mapView(HANDLE Proc, DWORD Permissions);
		bool unMapView(HANDLE Proc);

		void free();

		NTSTATUS getErr();
		std::size_t getSz();

		PVOID getRemoteAddr();
		PVOID getLocalAddr();
		void setRemoteAddr(void* set);
	};
}