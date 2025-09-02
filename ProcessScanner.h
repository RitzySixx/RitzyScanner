// ProcessScanner.h
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <set>
#include <map>

struct FileInfo {
    std::string path;
    std::string modTime;
    std::string signatureStatus;
    std::string trusted;
    bool fileExists;
    std::string sourceProcess;
    DWORD sourcePID;
};

namespace ProcessScanner {
    void SetConsoleColor(WORD color);
    void ResetConsoleColor();
    bool EnableDebugPrivilege();
    std::string GetFileModTime(const std::string& filePath);
    std::string CheckFileSignature(const std::string& filePath);
    std::string GetServiceNameFromPID(DWORD pid);
    DWORD GetServicePID(const char* name);
    std::map<DWORD, std::string> GetProcessList();
    std::string ConvertDevicePathToDriveLetter(const std::string& devicePath);
    std::set<std::string> ScanProcessMemory(DWORD pid);
    std::vector<FileInfo> ScanAllProcesses();
    void ExportToCSV(const std::vector<FileInfo>& files, const std::string& filename);
}