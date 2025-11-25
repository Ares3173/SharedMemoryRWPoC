#ifndef PROCESS_HPP
#define PROCESS_HPP

namespace proc
{

	class process
	{
		DWORD ID;
		utils::safeHandle Hwnd;
		const wchar_t* Name;
		HWND mainWindowHwnd;
	public:

		process(const wchar_t* Name) : Name(Name), ID(NULL), Hwnd(INVALID_HANDLE_VALUE){};

		process(DWORD ID) : ID(ID), Hwnd(INVALID_HANDLE_VALUE), Name(L"RobloxPlayerBeta.exe") {};

		DWORD getPID();
		utils::safeHandle getHandle(DWORD Flags = PROCESS_ALL_ACCESS);

		bool isMainWindowOpen();
		bool isProcessAliveExternal(bool throwExcept = true);

		bool isAttached();
		void markAttached();



		//std::uintptr_t getImageBaseAddress();
	};
}

#endif