// RegistryParser.h
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include <ctime>

struct RegistryEntry {
    std::string executionTime;
    std::string modificationTime;
    std::string application;
    std::string path;
    std::string signature;
    std::string trusted;
    std::string user;
    std::string sid;
    std::string regPath;
    std::string regType;
};

namespace RegistryParser {
    void SetConsoleColor(WORD color);
    void ResetConsoleColor();
    bool IsRunAsAdmin();
    std::string SidToUsername(const std::string& sidStr);
    std::string BytesToHex(const BYTE* data, size_t len);
    std::string FileTimeToString(FILETIME ft);
    std::string CheckFileSignature(const std::string& filePath);
    std::string GetFileModificationTime(const std::string& filePath);
    std::string CleanMuiCachePath(const std::string& path);
    std::vector<RegistryEntry> ParseAllRegistry();
    void ExportToCSV(const std::vector<RegistryEntry>& entries, const std::string& filename);
}