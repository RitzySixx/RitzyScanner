#include "ProcessScanner.h"
#include "EnhancedLogger.h"
#include <iostream>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <sys/stat.h>

using std::cout;
using std::cerr;
using std::endl;

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

// Optimized Process Memory Scanner
// Ultra-fast file path detection with chunked processing

namespace ProcessScanner {
    void SetConsoleColor(WORD color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void ResetConsoleColor() {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    bool EnableDebugPrivilege() {
        HANDLE thandle;
        LUID identidier;
        TOKEN_PRIVILEGES privileges{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thandle)) return false;
        if (!LookupPrivilegeValueW(0, SE_DEBUG_NAME, &identidier)) {
            CloseHandle(thandle);
            return false;
        }
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = identidier;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(thandle, 0, &privileges, sizeof(privileges), NULL, NULL)) {
            CloseHandle(thandle);
            return false;
        }
        CloseHandle(thandle);
        return true;
    }

    std::string GetFileModTime(const std::string& filePath) {
        struct stat fileInfo;
        if (stat(filePath.c_str(), &fileInfo) != 0) {
            return "Unknown";
        }

        std::tm timeInfo;
        localtime_s(&timeInfo, &fileInfo.st_mtime);

        std::ostringstream oss;
        oss << std::put_time(&timeInfo, "%m/%d/%Y %H:%M:%S");
        return oss.str();
    }

    std::string CheckFileSignature(const std::string& filePath) {
        return EnhancedLogger::CheckFileSignatureUnified(filePath);
    }

    std::string IsSignatureTrusted(std::string& signatureStatus, const std::string& filePath) {
        return EnhancedLogger::CheckFileTrustUnified(filePath, signatureStatus);
    }

    std::string GetServiceNameFromPID(DWORD pid) {
        if (pid == 0) return "";

        SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (schSCManager == NULL) return "";

        DWORD bytesNeeded = 0;
        DWORD servicesReturned = 0;
        EnumServicesStatusExA(schSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
            NULL, 0, &bytesNeeded, &servicesReturned, NULL, NULL);

        if (bytesNeeded == 0) {
            CloseServiceHandle(schSCManager);
            return "";
        }

        std::vector<BYTE> buffer(bytesNeeded);
        ENUM_SERVICE_STATUS_PROCESSA* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());
        if (!EnumServicesStatusExA(schSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
            buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, NULL, NULL)) {
            CloseServiceHandle(schSCManager);
            return "";
        }

        std::string serviceName;
        for (DWORD i = 0; i < servicesReturned; i++) {
            if (services[i].ServiceStatusProcess.dwProcessId == pid) {
                serviceName = services[i].lpServiceName;
                break;
            }
        }

        CloseServiceHandle(schSCManager);
        return serviceName;
    }

    DWORD GetServicePID(const char* name) {
        if (!name) return 0;

        SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (schSCManager == NULL) return 0;

        SC_HANDLE schService = OpenServiceA(schSCManager, name, SERVICE_QUERY_STATUS);
        if (schService == NULL) {
            CloseServiceHandle(schSCManager);
            return 0;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return 0;
        }

        DWORD pid = ssp.dwProcessId;
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return pid;
    }

    std::map<DWORD, std::string> GetProcessList() {
        std::map<DWORD, std::string> processList;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return processList;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return processList;
        }

        do {
            char exeName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
            processList[pe32.th32ProcessID] = exeName;
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return processList;
    }

    std::string ConvertDevicePathToDriveLetter(const std::string& devicePath) {
        std::vector<char> driveLetters(26);
        DWORD drives = GetLogicalDriveStringsA(26, driveLetters.data());

        for (DWORD i = 0; i < drives; i += 4) {
            char driveLetter = driveLetters[i];
            if (driveLetter == 0) continue;

            char volumePath[MAX_PATH];
            if (QueryDosDeviceA((std::string(1, driveLetter) + ":").c_str(), volumePath, MAX_PATH)) {
                if (devicePath.find(volumePath) == 0) {
                    std::string result = driveLetter + std::string(":") + devicePath.substr(strlen(volumePath));
                    std::replace(result.begin(), result.end(), '/', '\\');
                    return result;
                }
            }
        }
        return devicePath;
    }

    std::set<std::string> ScanProcessMemory(DWORD pid) {
        std::set<std::string> uniquePaths;
        HANDLE phandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!phandle) return uniquePaths;

        MEMORY_BASIC_INFORMATION info;
        for (SIZE_T address = 0; VirtualQueryEx(phandle, (LPVOID)address, &info, sizeof(info)); address += info.RegionSize) {
            if (info.State != MEM_COMMIT || info.RegionSize > 100 * 1024 * 1024) continue;

            std::vector<char> buffer(info.RegionSize);
            SIZE_T bytesRead;
            if (!ReadProcessMemory(phandle, (LPVOID)address, buffer.data(), info.RegionSize, &bytesRead)) continue;

            std::string memory(buffer.begin(), buffer.begin() + bytesRead);

            // Enhanced Drive letter paths with better detection
            for (size_t pos = 0; (pos = memory.find(":\\", pos + 1)) != std::string::npos; ) {
                if (pos < 1 || !isalpha(memory[pos - 1])) continue;

                std::string path;
                path.push_back(memory[pos - 1]);
                path += ":\\";

                __int64 endPos = pos + 2;
                while (endPos < memory.size() &&
                    (isalnum(memory[endPos]) || memory[endPos] == '\\' || memory[endPos] == '/' ||
                        memory[endPos] == '.' || memory[endPos] == '_' || memory[endPos] == '-' ||
                        memory[endPos] == ' ' || memory[endPos] == '(' || memory[endPos] == ')' ||
                        memory[endPos] == '"' || memory[endPos] == '\'' || memory[endPos] == '@' ||
                        memory[endPos] == '!' || memory[endPos] == '#' || memory[endPos] == '$' ||
                        memory[endPos] == '%' || memory[endPos] == '^' || memory[endPos] == '&' ||
                        memory[endPos] == '*' || memory[endPos] == '+' || memory[endPos] == '=' ||
                        memory[endPos] == '[' || memory[endPos] == ']' || memory[endPos] == '{' ||
                        memory[endPos] == '}' || memory[endPos] == '|' || memory[endPos] == ';' ||
                        memory[endPos] == ':' || memory[endPos] == ',')) {
                    path.push_back(memory[endPos]);
                    endPos++;
                }

                // Clean up trailing spaces and quotes
                while (!path.empty() && (path.back() == ' ' || path.back() == '"' || path.back() == '\'')) {
                    path.pop_back();
                }

                // Enhanced file extension detection
                if (path.length() > 5 && path.find('.') != std::string::npos) {
                    std::string ext = path.substr(path.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    // Expanded list of suspicious extensions
                    std::set<std::string> suspiciousExtensions = {
                        ".exe", ".dll", ".sys", ".cmd", ".bat", ".ps1", ".msi", ".com",
                        ".scr", ".pif", ".jar", ".zip", ".rar", ".7z", ".tar", ".gz",
                        ".vbs", ".js", ".wsf", ".hta", ".lnk", ".url", ".reg", ".inf",
                        ".cab", ".msp", ".msu", ".deb", ".rpm", ".pkg", ".dmg", ".iso",
                        ".img", ".vhd", ".vhdx", ".ova", ".ovf", ".qcow2", ".vdi", ".vmdk"
                    };

                    if (suspiciousExtensions.count(ext) > 0) {
                        uniquePaths.insert(path);
                    }
                }
            }

            // Enhanced Device paths with better pattern matching
            for (__int64 pos = 0; (pos = memory.find("\\Device\\HarddiskVolume", pos)) != std::string::npos; pos++) {
                __int64 endPos = pos + 1;
                while (endPos < memory.size() &&
                    (isalnum(memory[endPos]) || memory[endPos] == '\\' || memory[endPos] == '/' ||
                        memory[endPos] == '.' || memory[endPos] == '_' || memory[endPos] == '-' ||
                        memory[endPos] == ' ' || memory[endPos] == '(' || memory[endPos] == ')' ||
                        memory[endPos] == '"' || memory[endPos] == '\'' || memory[endPos] == '@' ||
                        memory[endPos] == '!' || memory[endPos] == '#' || memory[endPos] == '$' ||
                        memory[endPos] == '%' || memory[endPos] == '^' || memory[endPos] == '&' ||
                        memory[endPos] == '*' || memory[endPos] == '+' || memory[endPos] == '=' ||
                        memory[endPos] == '[' || memory[endPos] == ']' || memory[endPos] == '{' ||
                        memory[endPos] == '}' || memory[endPos] == '|' || memory[endPos] == ';' ||
                        memory[endPos] == ':' || memory[endPos] == ',')) {
                    endPos++;
                }

                std::string devicePath = memory.substr(pos, endPos - pos);
                std::string convertedPath = ConvertDevicePathToDriveLetter(devicePath);

                if (convertedPath != devicePath && convertedPath.length() > 3) {
                    std::string ext = convertedPath.substr(convertedPath.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    // Use same suspicious extensions list
                    std::set<std::string> suspiciousExtensions = {
                        ".exe", ".dll", ".sys", ".cmd", ".bat", ".ps1", ".msi", ".com",
                        ".scr", ".pif", ".jar", ".zip", ".rar", ".7z", ".tar", ".gz",
                        ".vbs", ".js", ".wsf", ".hta", ".lnk", ".url", ".reg", ".inf",
                        ".cab", ".msp", ".msu", ".deb", ".rpm", ".pkg", ".dmg", ".iso",
                        ".img", ".vhd", ".vhdx", ".ova", ".ovf", ".qcow2", ".vdi", ".vmdk"
                    };

                    if (suspiciousExtensions.count(ext) > 0) {
                        uniquePaths.insert(convertedPath);
                    }
                }
            }

        }

        CloseHandle(phandle);
        return uniquePaths;
    }

    bool FileExists(const std::string& path) {
        struct stat buffer;
        return (stat(path.c_str(), &buffer) == 0);
    }

    void ExportToCSV(const std::vector<FileInfo>& files, const std::string& filename) {
        std::ofstream csvFile(filename);
        if (!csvFile.is_open()) {
            std::cerr << "Failed to create CSV file: " << filename << std::endl;
            return;
        }

        csvFile << "Time,File Name,File Path,Signature Status,Trusted,File Exists,Source Process,Source PID\n";
        for (const auto& file : files) {
            std::string timelineTime;
            if (file.fileExists && file.modTime != "Unknown") {
                std::tm tm = {};
                std::istringstream ss(file.modTime);
                ss >> std::get_time(&tm, "%m/%d/%Y %H:%M:%S");
                if (!ss.fail()) {
                    std::ostringstream oss;
                    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
                    timelineTime = oss.str();
                }
                else {
                    timelineTime = file.modTime;
                }
            }

            std::string escapedPath = file.path;
            size_t pos = 0;
            while ((pos = escapedPath.find('"', pos)) != std::string::npos) {
                escapedPath.replace(pos, 1, "\"\"");
                pos += 2;
            }

            csvFile << "\"" << timelineTime << "\","
                << "\"" << escapedPath.substr(escapedPath.find_last_of("\\/") + 1) << "\","
                << "\"" << escapedPath << "\","
                << "\"" << file.signatureStatus << "\","
                << "\"" << file.trusted << "\","
                << "\"" << (file.fileExists ? "Yes" : "No") << "\","
                << "\"" << file.sourceProcess << "\","
                << "\"" << file.sourcePID << "\"\n";
        }

        csvFile.close();
        std::cout << "Exported " << files.size() << " entries to " << filename << std::endl;
    }

    std::vector<FileInfo> ScanAllProcesses() {
        std::vector<FileInfo> allFileInfo;
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        if (!EnableDebugPrivilege()) {
            SetConsoleColor(FOREGROUND_RED);
            std::cout << "Process scanning requires admin privileges." << std::endl;
            ResetConsoleColor();
            return allFileInfo;
        }

        std::vector<std::string> services = {
            "PcaSvc", "DiagTrack", "WSearch", "WinDefend",
            "wuauserv", "EventLog", "Schedule"
        };

        std::vector<std::string> importantProcesses = {
            "explorer.exe", "svchost.exe", "dllhost.exe",
            "lsass.exe", "csrss.exe", "winlogon.exe",
            "services.exe", "spoolsv.exe"
        };

        std::set<std::string> globalPathsFound;
        auto processList = GetProcessList();

        // Scan services
        for (const auto& service : services) {
            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            cout << "Scanning service: " << service << endl;
            ResetConsoleColor();

            DWORD pid = GetServicePID(service.c_str());
            if (pid > 0) {
                auto filePaths = ScanProcessMemory(pid);
                for (const auto& path : filePaths) {
                    if (globalPathsFound.find(path) == globalPathsFound.end()) {
                        globalPathsFound.insert(path);

                        FileInfo info;
                        info.path = path;
                        info.fileExists = FileExists(path);
                        info.modTime = info.fileExists ? GetFileModTime(path) : "";
                        info.signatureStatus = info.fileExists ? CheckFileSignature(path) : "DELETED";
                        if (info.signatureStatus == "DELETED") {
                            info.trusted = ""; // deleted file, leave blank
                        }
                        else if (info.signatureStatus == "Invalid") {
                            info.trusted = "Untrusted"; // no digital signature
                        }
                        else {
                            info.trusted = IsSignatureTrusted(info.signatureStatus, path); // signed file, check trust
                        }
                        info.sourceProcess = service;
                        info.sourcePID = pid;
                        allFileInfo.push_back(info);

                        // Enhanced logging for problematic entries
                        if (EnhancedLogger::IsProblematicEntry(info.signatureStatus, info.trusted)) {
                            std::string issueType;
                            if (info.signatureStatus == "DELETED") {
                                issueType = "DELETED";
                            } else if (info.signatureStatus == "Invalid" || info.trusted == "Untrusted") {
                                issueType = "INVALID_SIGNATURE";
                            } else if (info.trusted == "Unsigned") {
                                issueType = "UNSIGNED";
                            } else {
                                issueType = "UNTRUSTED";
                            }

                            if (!EnhancedLogger::IsDuplicateEntry(path, issueType)) {
                                DetailedLogEntry logEntry = {};
                                logEntry.timestamp = EnhancedLogger::GetCurrentTimestamp();
                                logEntry.scanType = "ProcessMemory";
                                logEntry.source = "Service: " + service;
                                logEntry.filePath = path;
                                logEntry.issueType = issueType;
                                logEntry.signatureStatus = info.signatureStatus;
                                logEntry.trustedStatus = info.trusted;
                                logEntry.fileSize = info.fileExists ? EnhancedLogger::GetFileSize(path) : "N/A";
                                logEntry.modificationTime = info.modTime;
                                logEntry.md5Hash = info.fileExists ? EnhancedLogger::CalculateFileHash(path, "MD5") : "N/A";
                                logEntry.sha256Hash = info.fileExists ? EnhancedLogger::CalculateFileHash(path, "SHA256") : "N/A";
                                logEntry.additionalInfo = EnhancedLogger::GetDetailedFileInfo(path);
                                logEntry.fileExists = info.fileExists;
                                logEntry.sourcePID = pid;

                                EnhancedLogger::CollectProblematicEntry(logEntry);
                                EnhancedLogger::AddToGlobalTracking(path, issueType);
                            }
                        }
                    }
                }
            }
        }

        // Scan important processes
        for (const auto& process : processList) {
            std::string processName = process.second;
            DWORD pid = process.first;

            if (std::find(importantProcesses.begin(), importantProcesses.end(), processName) != importantProcesses.end()) {
                SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << "Scanning process: " << processName << " (PID: " << pid << ")" << std::endl;
                ResetConsoleColor();

                std::string displayName = processName;
                if (processName == "svchost.exe") {
                    std::string serviceName = GetServiceNameFromPID(pid);
                    if (!serviceName.empty()) {
                        displayName = "svchost.exe (" + serviceName + ")";
                    }
                }

                auto filePaths = ScanProcessMemory(pid);
                for (const auto& path : filePaths) {
                    if (globalPathsFound.find(path) == globalPathsFound.end()) {
                        globalPathsFound.insert(path);

                        FileInfo info;
                        info.path = path;
                        info.fileExists = FileExists(path);
                        info.modTime = info.fileExists ? GetFileModTime(path) : "";
                        info.signatureStatus = info.fileExists ? CheckFileSignature(path) : "DELETED";
                        if (info.signatureStatus == "DELETED") {
                            info.trusted = ""; // deleted file, leave blank
                        }
                        else if (info.signatureStatus == "Invalid") {
                            info.trusted = "Untrusted"; // no digital signature
                        }
                        else {
                            info.trusted = IsSignatureTrusted(info.signatureStatus, path); // signed file, check trust
                        }
                        info.sourceProcess = displayName;
                        info.sourcePID = pid;
                        allFileInfo.push_back(info);

                        // Enhanced logging for problematic entries
                        if (EnhancedLogger::IsProblematicEntry(info.signatureStatus, info.trusted)) {
                            std::string issueType;
                            if (info.signatureStatus == "DELETED") {
                                issueType = "DELETED";
                            } else if (info.signatureStatus == "Invalid" || info.trusted == "Untrusted") {
                                issueType = "INVALID_SIGNATURE";
                            } else if (info.trusted == "Unsigned") {
                                issueType = "UNSIGNED";
                            } else {
                                issueType = "UNTRUSTED";
                            }

                            if (!EnhancedLogger::IsDuplicateEntry(path, issueType)) {
                                DetailedLogEntry logEntry = {};
                                logEntry.timestamp = EnhancedLogger::GetCurrentTimestamp();
                                logEntry.scanType = "ProcessMemory";
                                logEntry.source = "Process: " + displayName;
                                logEntry.filePath = path;
                                logEntry.issueType = issueType;
                                logEntry.signatureStatus = info.signatureStatus;
                                logEntry.trustedStatus = info.trusted;
                                logEntry.fileSize = info.fileExists ? EnhancedLogger::GetFileSize(path) : "N/A";
                                logEntry.modificationTime = info.modTime;
                                logEntry.md5Hash = info.fileExists ? EnhancedLogger::CalculateFileHash(path, "MD5") : "N/A";
                                logEntry.sha256Hash = info.fileExists ? EnhancedLogger::CalculateFileHash(path, "SHA256") : "N/A";
                                logEntry.additionalInfo = EnhancedLogger::GetDetailedFileInfo(path);
                                logEntry.fileExists = info.fileExists;
                                logEntry.sourcePID = pid;

                                EnhancedLogger::CollectProblematicEntry(logEntry);
                                EnhancedLogger::AddToGlobalTracking(path, issueType);
                            }
                        }
                    }
                }
            }
        }

        // Generate CSV filename without timestamp
        std::string filename = "ProcessMemoryScan.csv";

        ExportToCSV(allFileInfo, filename);
        return allFileInfo;
    }
}