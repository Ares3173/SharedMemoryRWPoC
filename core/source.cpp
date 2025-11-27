#include "pch.h"
#include "watcher/watcher.hpp"
#include "process/process.hpp"
#include "memory/memory.h"
#include "internal/internal.h"

uintptr_t FindCodeCave(HANDLE Process) {
    HMODULE Modules[1024];

    DWORD Bytes;
    if (!EnumProcessModules(Process, Modules, sizeof(Modules), &Bytes))
        return 0;

    MODULEINFO ModInfo;

    GetModuleInformation(Process, Modules[0], &ModInfo, sizeof(ModInfo));
    uintptr_t Base = (uintptr_t)Modules[0];

    std::vector< uint8_t > Header(0x1000);

    SIZE_T Read;
    ReadProcessMemory(Process, (LPCVOID)Base, Header.data(), 0x1000, &Read);

    uintptr_t SecondView = 0;
    for (MEMORY_BASIC_INFORMATION Mem; VirtualQueryEx(Process, (LPCVOID)SecondView, &Mem, sizeof(Mem));
        SecondView = (uintptr_t)Mem.BaseAddress + Mem.RegionSize) {

        if (Mem.State != MEM_COMMIT || Mem.Type != MEM_MAPPED || (uintptr_t)Mem.BaseAddress == Base || Mem.RegionSize != ModInfo.SizeOfImage)
            continue;

        std::vector< uint8_t > Check(0x1000);
        if (ReadProcessMemory(Process, Mem.BaseAddress, Check.data(), 0x1000, &Read) && memcmp(Header.data(), Check.data(), 0x1000) == 0) {
            SecondView = (uintptr_t)Mem.BaseAddress;
            break;
        }
    }

    if (!SecondView)
        return 0;

    LOG("SecondView: 0x{:X}", SecondView);

    for (uintptr_t Address = 0;; ) {
        MEMORY_BASIC_INFORMATION Mem;
        if (!VirtualQueryEx(Process, (LPCVOID)Address, &Mem, sizeof(Mem)))
            break;

        uintptr_t Region = (uintptr_t)Mem.BaseAddress;
        Address = Region + Mem.RegionSize;

        if (Region < Base || Region >= Base + ModInfo.SizeOfImage || Mem.State != MEM_COMMIT || Mem.Protect != PAGE_EXECUTE_READWRITE || Mem.RegionSize < 256)
            continue;

        std::vector< uint8_t > Buffer(Mem.RegionSize);
        if (!ReadProcessMemory(Process, Mem.BaseAddress, Buffer.data(), Mem.RegionSize, &Read))
            continue;

        for (size_t i = 0, Zeros = 0; i < Read; ++i) {
            if ((Zeros = Buffer[i] == 0 ? Zeros + 1 : 0) == 256) /* Minimum size of 256 bytes */
                return SecondView + (Region + i - 255 - Base); /* Rebase to second view, since when using VirtualQueryEx the entire second view will appear as one large mapped region */
        }
    }

    return 0;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ PSTR lpCmdLine,
	_In_ int nShowCmd
)
{
#if USE_DEBUGGING
	AllocConsole();
	spdlog::set_level(spdlog::level::debug);
#endif
	LOG("Running");

	utils::threadSafeVector<DWORD> currentProcesses;

	bool watcherStarted = watcher::StartProcessWatcher([&](DWORD pid) {
		auto snap = currentProcesses.snapshot();
			if (std::find(snap.begin(), snap.end(), pid) == snap.end()) {
				currentProcesses.push_back(pid);

				const auto target = std::make_unique<proc::process>(pid);
				LOG("Found Process: 0x{:X}", target->getPID());

                std::uint8_t* const codeCave = reinterpret_cast<std::uint8_t*>(FindCodeCave(target->getHandle()));
                LOG("Cave Code: {}", fmt::ptr(codeCave));


                //Create Read Shared Page
                const auto readShared = std::make_shared<memory::section>(0x1000);
                if (!readShared->create()) { CRITICAL("Failed to create readShared Page"); }
                if (!readShared->mapView(NtCurrentProcess(), PAGE_READWRITE)) { CRITICAL("Failed to map readShared to current process"); }
                if (!readShared->mapView(target->getHandle(), PAGE_READONLY)) { CRITICAL("Failed to map readShared to roblox process"); }
                LOG("Created ReadShared Page. Local: {} Remote: {}", fmt::ptr(readShared->getLocalAddr()), fmt::ptr(readShared->getRemoteAddr()));

                ZeroMemory(readShared->getLocalAddr(), 0x1000);

                const auto writeShared = std::make_shared<memory::section>(0x1000);
                if (!writeShared->create()) { CRITICAL("Failed to create writeShared Page"); }
                if (!writeShared->mapView(NtCurrentProcess(), PAGE_READONLY)) { CRITICAL("Failed to map writeShared to current process"); }
                if (!writeShared->mapView(target->getHandle(), PAGE_READWRITE)) { CRITICAL("Failed to map writeShared to roblox process"); }
                LOG("Created WriteShared Page. Local: {} Remote: {}", fmt::ptr(writeShared->getLocalAddr()), fmt::ptr(writeShared->getRemoteAddr()));

                ZeroMemory(writeShared->getLocalAddr(), 0x1000);

                auto readList = reinterpret_cast<std::uintptr_t*>(readShared->getLocalAddr());
                auto writeList = reinterpret_cast<std::uintptr_t*>(writeShared->getLocalAddr());
                readList[0] = 0;

                internal::attach(target.get(), 0x0, codeCave, reinterpret_cast<std::uintptr_t>(writeShared->getRemoteAddr()), reinterpret_cast<std::uintptr_t>(readShared->getRemoteAddr()));

                //while (true)
                //{
                //    LOG("Current Job: 0x{:X}", writeList[0]);
                //}
			}
		}, true);

	return 0;
}