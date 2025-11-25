#ifndef WATCHER_HPP
#define WATCHER_HPP

#include <windows.h>
#include <tlhelp32.h>
#include <functional>
#include <thread>
#include <atomic>
#include <string>

namespace watcher
{
    inline std::atomic<bool> g_running{ false };

    std::vector<uint32_t> listPidsByName(const std::wstring& imageName) {
        std::vector<uint32_t> out;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return out;

        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, imageName.c_str()) == 0) {
                    if (pe.th32ProcessID) out.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return out;
    }

    inline bool StartProcessWatcher(const std::function<void(uint32_t)>& callback, bool sameThread = false)
    {
        if (g_running.exchange(true))
            return false;
        if (!sameThread)
        {
            std::thread([callback]() {
                while (true) {
                    auto pids = listPidsByName(L"RobloxPlayerBeta.exe");
                    for (uint32_t pid : pids) {
                        callback(pid);
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                }).detach();
        }
        else
        {
            while (true) {
                auto pids = listPidsByName(L"RobloxPlayerBeta.exe");
                for (uint32_t pid : pids) {
                    callback(pid);
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        return true;
    }

    inline void StopProcessWatcher()
    {
        g_running = false;
    }
}

#endif
