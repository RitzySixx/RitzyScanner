// jumplistparser.h
#pragma once
#include <windows.h>
#include <vector>
#include <string>

struct JumplistEntry {
    std::wstring path;
    std::wstring title;
    std::wstring arguments;
    std::wstring workingDir;
    std::wstring iconPath;
    int iconIndex;
    FILETIME creationTime;
    FILETIME accessTime;
    FILETIME writeTime;
    std::wstring appId;
    std::wstring signatureStatus;
    std::wstring trusted;
    std::wstring jumplistFile;
    std::wstring entryType;
    std::wstring lnkPath;
    FILETIME jumplistTimestamp;
    long long fileSize = -1; // New: File size in bytes
    std::wstring sha256; // New: SHA256 hash hex
};

namespace JumpListParser {
    std::string WideToUTF8(const std::wstring& wstr);
    std::wstring GetSystemTimeString(const FILETIME& ft);
    std::wstring GetFileNameFromPath(const std::wstring& path);
    std::wstring GetFileExtension(const std::wstring& path);
    std::string CheckFileSignature(const std::wstring& filePath);
    std::vector<JumplistEntry> ParseAllJumpLists();
    void ExportToCSV(const std::vector<JumplistEntry>& entries, const std::wstring& outputPath);
}