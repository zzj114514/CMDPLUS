#pragma once
#ifndef GARBAGE_CLEANER_H
#define GARBAGE_CLEANER_H

#include "CommonDefs.h"
#include <string>
#include <vector>
#include <set>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>
#include <filesystem>

// ============================================================================
// GarbageCleaner — 系统垃圾文件扫描与清理
//   扫描 Windows 临时目录、浏览器缓存、软件缓存等并批量清理
//   支持多线程扫描 + Windows 线程池删除
// ============================================================================

class GarbageCleaner {
public:
    struct GarbageFileInfo {
        std::wstring path;
        uint64_t size;
        std::wstring category;
        std::wstring description;
    };

    struct ScanProgress {
        std::atomic<uint64_t> scannedFiles{0};
        std::atomic<uint64_t> foundFiles{0};
        std::atomic<uint64_t> totalSize{0};
        std::atomic<int> runningThreads{0};
        std::chrono::steady_clock::time_point startTime;
    };

private:
    static ScanProgress g_progress;
    static std::vector<GarbageFileInfo> g_garbageFiles;
    static std::mutex g_mutex;
    static std::atomic<bool> g_stopRequested;

    struct ScanTarget {
        std::wstring path;
        std::wstring category;
        std::wstring description;
        std::vector<std::wstring> extensions;
        bool scanSubdirs;
        int maxDepth;
    };

    struct DeleteTaskContext {
        std::wstring path;
        uint64_t size;
        std::atomic<int>* deletedCount;
        std::atomic<int>* failedCount;
        std::atomic<uint64_t>* deletedSize;
        std::atomic<int>* processedCount;
        std::atomic<bool>* stopFlag;
        int totalCount;
    };

    // --- 内联简单辅助方法 ---

    static bool IsFileInUse(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            return false;
        }
        return GetLastError() == ERROR_SHARING_VIOLATION ||
               GetLastError() == ERROR_LOCK_VIOLATION;
    }

    static bool IsSystemFile(const std::wstring& path) {
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        static const std::vector<std::wstring> protectedPaths = {
            L"\\windows\\system32\\",
            L"\\windows\\syswow64\\",
            L"\\program files\\",
            L"\\program files (x86)\\",
            L"\\windows\\winsxs\\",
            L"\\programdata\\microsoft\\",
            L"\\$recycle.bin\\",
            L"\\system volume information\\",
            L"\\PerfLogs\\"
        };

        for (const auto& protectedPath : protectedPaths) {
            if (lowerPath.find(protectedPath) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    static bool MatchExtension(const std::wstring& filename,
                               const std::vector<std::wstring>& extensions) {
        if (extensions.empty()) return false;
        if (extensions[0] == L"*") return true;

        std::wstring lowerName = filename;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (const auto& ext : extensions) {
            std::wstring lowerExt = ext;
            std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::towlower);

            if (lowerExt[0] == L'.') {
                if (lowerName.size() >= lowerExt.size() &&
                    lowerName.compare(lowerName.size() - lowerExt.size(),
                                      lowerExt.size(), lowerExt) == 0) {
                    return true;
                }
            } else {
                if (lowerName.find(lowerExt) != std::wstring::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    static bool SafeDeleteFile(const std::wstring& path) {
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            return true;
        }
        if (DeleteFileW(path.c_str()) != 0) {
            return true;
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return true;
        }
        if (attr & FILE_ATTRIBUTE_READONLY) {
            SetFileAttributesW(path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
            if (DeleteFileW(path.c_str()) != 0) {
                return true;
            }
        }
        return false;
    }

    static bool SafeRemoveDirectory(const std::wstring& path) {
        if (IsFileInUse(path)) {
            return false;
        }
        std::wstring attribCmd = L"attrib -H -S -R \"" + path + L"\" /s /d 2>nul";
        _wsystem(attribCmd.c_str());
        return RemoveDirectoryW(path.c_str()) != 0;
    }

    static std::wstring FormatSize(uint64_t bytes) {
        const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
        int unitIndex = 0;
        double size = static_cast<double>(bytes);

        while (size >= 1024 && unitIndex < 4) {
            size /= 1024;
            unitIndex++;
        }

        wchar_t buffer[32];
        swprintf_s(buffer, L"%.2f %s", size, units[unitIndex]);
        return buffer;
    }

    // --- 复杂方法（仅声明，实现在 .cpp） ---

    static std::vector<ScanTarget> GetScanTargets();
    static void ScanDirectory(const ScanTarget& target,
                              std::vector<GarbageFileInfo>& localFiles,
                              int currentDepth = 0);
    static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
    static void CALLBACK DeleteFileCallback(PTP_CALLBACK_INSTANCE instance,
                                             PVOID context);
    static void BatchDeleteByDirectory(const std::vector<GarbageFileInfo>& files,
                                       int& deletedCount, int& failedCount,
                                       uint64_t& deletedSize,
                                       int maxCmdLength = 6000);

public:
    static void StartCleanup();
};

#endif // GARBAGE_CLEANER_H
