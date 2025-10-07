#pragma once
#include "utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <set>
#include <map>
#include <chrono>
#include <iomanip>
#include <thread>
#include <future>
#include <locale>
#include <codecvt>

struct StringMatch {
    std::string detectionName;
    std::string processName;
};

// Console color management
class ConsoleColor {
private:
    HANDLE hConsole;
    WORD originalAttributes;
public:
    ConsoleColor();
    ~ConsoleColor();
    void setColor(WORD color);
};

struct DetectionString {
    std::string name;
    std::string pattern;
    std::string patternLower; // Pre-computed lowercase version
    std::wstring patternWide; // Wide string version for Unicode detection
};

struct ScanResult {
    std::string detectionName;
    std::string processName;
    DWORD processId;
    std::string pattern;
    std::string matchType;
};

class MemoryScanner {
private:
    std::map<std::string, std::vector<DetectionString>> processDetections;

public:
    MemoryScanner();
    std::vector<ScanResult> ScanAllProcesses();

private:
    void InitializeDetections();
    static std::wstring StringToWide(const std::string& str);
    static std::string WideToString(const std::wstring& wstr);
    bool EnableDebugPrivilege();
    std::string ToLower(const std::string& str);
    std::wstring ToLower(const std::wstring& wstr);
    bool MeetsMinimumLength(const std::string& pattern);
    bool ContainsPatternFast(const std::string& contentLower, const DetectionString& detection);
    bool ContainsPatternUnicode(const std::wstring& contentWideLower, const DetectionString& detection);
    bool ContainsExtendedUnicode(const std::string& content, const DetectionString& detection);
    bool IsRegionStringLike(const std::vector<BYTE>& buffer, size_t bytesRead);
    DWORD GetServicePID(const std::string& serviceName);
    DWORD GetExplorerPID();
    std::string GetProcessName(DWORD pid);
    std::vector<ScanResult> ScanServiceMemory(DWORD pid, const std::string& processType, const std::vector<DetectionString>& detections);
    std::vector<ScanResult> ScanExplorerMemory(DWORD pid, const std::string& processType, const std::vector<DetectionString>& detections);
};

std::vector<StringMatch> ScanProcessesAndServicesForStrings();