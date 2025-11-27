#include "../pch.h"
#include "internal.h"

#include "../process/process.hpp"

namespace internal
{

	std::size_t getAsmSz(void* Asm)
	{
		std::size_t AsmSz = 0;
		for (std::uint8_t* i = static_cast<std::uint8_t*>(Asm); AsmSz == 0; i++)
		{
			if (i[0] == 0x90 && i[1] == 0x90 && i[2] == 0x90 && i[3] == 0x90)
				return static_cast<std::size_t>(i - static_cast<std::uint8_t*>(Asm));
		}
		return AsmSz;
	}

    bool attach(proc::process* p, std::uintptr_t target, std::uint8_t* codeCave, std::uintptr_t writePage, std::uintptr_t readPage)
    {
		constexpr std::size_t structSize = sizeof(helper_t);
		const static std::size_t asmSize = getAsmSz(&internal_shell);

		DEBUG("Shell Sz: 0x{:X}", asmSize);

		std::uintptr_t originalAddress = 0;

		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(p->getHandle(), reinterpret_cast<void*>(target), &originalAddress, sizeof(std::uintptr_t), &bytesRead) || bytesRead != sizeof(std::uintptr_t))
		{
			ERROR("Failed to read original, Error: 0x{:X}", GetLastError());
			return false;
		}

		helper_t local{
			.readPage = readPage,
			.writePage = writePage,
			.original = originalAddress,
		};

		SIZE_T bytesWritten = 0;
		if (!WriteProcessMemory(p->getHandle(), codeCave, &internal_shell, asmSize, &bytesWritten) || bytesWritten != asmSize)
		{
			ERROR("Failed to write shell, Error: 0x{:X}", GetLastError());
			return false;
		}

		if (!WriteProcessMemory(p->getHandle(), codeCave + asmSize, &local, structSize, &bytesWritten) || bytesWritten != structSize)
		{
			ERROR("Failed to write helper, Error: 0x{:X}", GetLastError());
			return false;
		}

		LOG("Shell @ {} - Helper @ {}", fmt::ptr(codeCave), fmt::ptr(codeCave + asmSize));

		if (!WriteProcessMemory(p->getHandle(), reinterpret_cast<void*>(target), codeCave, sizeof(std::uintptr_t), &bytesWritten) || bytesWritten != sizeof(std::uintptr_t))
		{
			ERROR("Failed to write new, Error: 0x{:X}", GetLastError());
			return false;
		}
		return true;
    }
}