#include "DiscordDownloads.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <chrono>
#include <iomanip>

// Discord CDN URL pattern - Only match cdn.discordapp.com/attachments URLs
const std::regex DISCORD_CDN_PATTERN(
    R"(https://cdn\.discordapp\.com/attachments/\d+/\d+/([^?\s]+))",
    std::regex_constants::icase
);


// Get Discord process with highest memory usage
DWORD GetLargestDiscordProcess() {
    DWORD largestPID = 0;
    SIZE_T largestMemory = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::string processName;
#ifdef UNICODE
            std::wstring wProcessName(pe.szExeFile);
            processName = std::string(wProcessName.begin(), wProcessName.end());
#else
            processName = pe.szExeFile;
#endif
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            if (processName.find("discord") != std::string::npos) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        SIZE_T memoryUsageKB = pmc.WorkingSetSize / 1024;
                        if (memoryUsageKB > largestMemory) {
                            largestMemory = memoryUsageKB;
                            largestPID = pe.th32ProcessID;
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return largestPID;
}


// Get process name from PID
std::string GetProcessNameFromPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return "Unknown";
    }

    char processName[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string result = "Unknown";

    if (GetProcessImageFileNameA(hProcess, processName, size) > 0) {
        result = processName;
        size_t lastSlash = result.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            result = result.substr(lastSlash + 1);
        }
    }

    CloseHandle(hProcess);
    return result;
}

// Extract Discord CDN URLs from memory content
std::vector<std::string> ExtractDiscordURLs(const std::string& content) {
    std::vector<std::string> urls;

    // Search for Discord CDN pattern only
    std::sregex_iterator begin(content.begin(), content.end(), DISCORD_CDN_PATTERN);
    std::sregex_iterator end;

    for (std::sregex_iterator i = begin; i != end; ++i) {
        std::smatch match = *i;
        if (match.size() > 1) {
            std::string filename = match[1].str();
            if (!filename.empty()) {
                urls.push_back(filename);
            }
        }
    }

    return urls;
}

// Scan Discord process memory for Discord CDN filenames
std::vector<DiscordDownload> ScanDiscordProcessMemory(DWORD pid) {
    std::vector<DiscordDownload> downloads;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return downloads;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T offset = 0;
    const SIZE_T MAX_REGION_SIZE = 50 * 1024 * 1024; // 50MB for Discord processes

    std::string processName = GetProcessNameFromPID(pid);

    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize <= MAX_REGION_SIZE && mbi.RegionSize > 0) {

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                std::string content(buffer.begin(), buffer.begin() + bytesRead);

                // Extract Discord CDN filenames from this memory region
                auto filenames = ExtractDiscordURLs(content);

                for (const auto& filename : filenames) {
                    // Get current timestamp
                    auto now = std::chrono::system_clock::now();
                    auto time_t_now = std::chrono::system_clock::to_time_t(now);
                    std::stringstream timestamp_ss;
                    std::tm time_info;
                    localtime_s(&time_info, &time_t_now);
                    timestamp_ss << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S");

                    downloads.push_back({
                        "https://cdn.discordapp.com/attachments/.../" + filename,
                        filename,
                        processName,
                        pid,
                        timestamp_ss.str()
                    });
                }
            }
        }

        offset += mbi.RegionSize;
        if (offset == 0) break; // Overflow protection
    }

    CloseHandle(hProcess);
    return downloads;
}

// Main function to extract Discord downloads from the largest Discord process
std::vector<DiscordDownload> ExtractDiscordDownloads() {
    std::vector<DiscordDownload> allDownloads;

    // Get Discord process with highest memory usage
    DWORD largestDiscordPID = GetLargestDiscordProcess();

    if (largestDiscordPID == 0) {
        return allDownloads;
    }

    // Scan the largest Discord process
    allDownloads = ScanDiscordProcessMemory(largestDiscordPID);

    return allDownloads;
}

// Enhanced version with more comprehensive scanning
std::vector<DiscordDownload> ExtractDiscordDownloadsEnhanced() {
    return ExtractDiscordDownloads(); // For now, same as basic version
}

// Create CSV file with Discord downloads
void CreateDiscordDownloadsCSV(const std::vector<DiscordDownload>& downloads) {
    std::ofstream csvFile("DiscordDownloads.csv");
    if (!csvFile.is_open()) {
        return;
    }

    // Write each filename.ext entry
    for (const auto& download : downloads) {
        csvFile << download.fileName << "\n";
    }

    csvFile.close();
}