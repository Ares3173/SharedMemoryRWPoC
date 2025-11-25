#include "../pch.h"
#include "Process.hpp"

namespace proc
{

	utils::safeHandle process::getHandle(DWORD Flags)
	{
		if (!Hwnd)
			Hwnd = OpenProcess(Flags, false, ID);
		return Hwnd;
	}

	bool process::isProcessAliveExternal(bool throwExcept)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ID);
		if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
			return false;

		DWORD exitCode = 0;
		bool isAlive = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
		CloseHandle(hProcess);
		return isAlive;
	}

	struct windowData
	{
		DWORD PID;
		HWND windowHwnd;
	};

	BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
		DWORD processId = 0;
		windowData* proc = reinterpret_cast<windowData*>(lParam);
		GetWindowThreadProcessId(hWnd, &processId);

		if (processId == proc->PID) {
			if (IsWindowVisible(hWnd) && GetWindow(hWnd, GW_OWNER) == nullptr) {
				proc->windowHwnd = hWnd;
				return FALSE;
			}
		}
		return TRUE;
	}


	bool process::isMainWindowOpen()
	{
		windowData temp {
		.PID = getPID(),
		.windowHwnd = nullptr
		};

		EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&temp));
		if (temp.windowHwnd == nullptr)
			return false;
		mainWindowHwnd = temp.windowHwnd;
		return true;
	}

	DWORD process::getPID()
	{
		return ID;
	}

	bool process::isAttached()
	{
		//auto addr = reinterpret_cast<std::uintptr_t>(getPEB().address) + (offsetof(_PEB64, Padding3) + 4);

		std::uint32_t value{};
		//if (!readDataWithPreSet(addr, &value, sizeof(value), true))
		//	return false;
		//LOG("Result1: 0x{:X}", value);
		return value == 0x1337;
	}



	void process::markAttached()
	{
		//std::uint32_t marker = 0x1337;
		//auto addr = reinterpret_cast<std::uintptr_t>(getPEB().address) + (offsetof(_PEB64, Padding3) + 4);
		//writeDataWithPreSet(addr, &marker, sizeof(marker), true);
		//std::uint32_t value{};
		//readDataWithPreSet(addr, &value, sizeof(value), true);
		//LOG("Result2: 0x{:X}", value);
	}

}