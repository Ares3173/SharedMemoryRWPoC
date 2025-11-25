add_executable(Core WIN32
pch.h
source.cpp

utils/utils.hpp

watcher/watcher.hpp

process/process.hpp 
process/process.cpp

memory/memory.h
memory/memory.cpp

ntdll/defs.h
ntdll/defsWin10.h
ntdll/defsWin11.h
ntdll/funcs.h

secure/syscalls.cpp
secure/syscalls.hpp
secure/syscallstubs.asm)

target_link_libraries(Core PRIVATE spdlog::spdlog)

target_compile_features(Core PRIVATE cxx_std_23)