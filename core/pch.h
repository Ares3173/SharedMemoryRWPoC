#pragma once
//External Includes

#include <WinSock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <psapi.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <streambuf>
#include <emmintrin.h>
#include <chrono>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <concurrent_queue.h>
#include <set>
#include <filesystem>
#include <conio.h>
#include <TlHelp32.h>
#include <type_traits>
#include <map>
#include <shlobj_core.h>
#include <KnownFolders.h>
#include <filesystem>
#include <optional>
#include <bit>

#define USE_DEBUGGING true
#define PROCESS_NAME L""

#undef ERROR
#if USE_DEBUGGING
#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <spdlog/sinks/basic_file_sink.h>

#define LOG(...) spdlog::info(__VA_ARGS__)
#define WARN(...) spdlog::warn(__VA_ARGS__)
#define DEBUG(...) spdlog::debug(__VA_ARGS__)
#define TRACE(...) spdlog::trace(__VA_ARGS__)
#define ERROR(...) spdlog::error(__VA_ARGS__)
#define CRITICAL(...) spdlog::critical(__VA_ARGS__); system("pause"); exit(1)
#else
#define LOG(...) (void*)0  
#define WARN(...) (void*)0
#define DEBUG(...) (void*)0
#define TRACE(...) (void*)0
#define ERROR(...) (void*)0
#define CRITICAL(...) exit(1);
#endif

#include "ntdll/funcs.h"
#include "secure/syscalls.hpp"
#include "utils/utils.hpp"