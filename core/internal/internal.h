#pragma once

namespace proc
{
    class process;
}

extern "C" void internal_shell(VOID);


namespace internal
{

    struct helper_t
    {
        std::uintptr_t readPage;
        std::uintptr_t writePage;
        std::uintptr_t original;
    };

    bool attach(proc::process* p, std::uintptr_t target, std::uint8_t* codeCave, std::uintptr_t writePage, std::uintptr_t readPage);
}