#include "ProcessScanner.h"
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
        WINTRUST_FILE_INFO fileData;
        memset(&fileData, 0, sizeof(fileData));
        fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileData.pcwszFilePath = std::wstring(filePath.begin(), filePath.end()).c_str();
        fileData.hFile = NULL;
        fileData.pgKnownSubject = NULL;

        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA winTrustData;
        memset(&winTrustData, 0, sizeof(winTrustData));
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN |
            WTD_HASH_ONLY_FLAG |
            WTD_USE_DEFAULT_OSVER_CHECK |
            WTD_LIFETIME_SIGNING_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL;
        winTrustData.pFile = &fileData;

        LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        if (lStatus == ERROR_SUCCESS) {
            winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);
            return "Valid (Authenticode)";
        }

        HCATADMIN hCatAdmin;
        if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
            HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwHashSize;
                if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0)) {
                    BYTE* pbHash = new BYTE[dwHashSize];
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0)) {
                        CATALOG_INFO catalogInfo;
                        memset(&catalogInfo, 0, sizeof(catalogInfo));
                        catalogInfo.cbStruct = sizeof(catalogInfo);

                        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
                        if (hCatInfo) {
                            CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0);
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                            delete[] pbHash;
                            CloseHandle(hFile);
                            CryptCATAdminReleaseContext(hCatAdmin, 0);
                            return "Valid (Catalog)";
                        }
                    }
                    delete[] pbHash;
                }
                CloseHandle(hFile);
            }
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }

        return "Invalid";
    }

    std::string GetServiceNameFromPID(DWORD pid) {
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
        HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if (!phandle) return uniquePaths;

        MEMORY_BASIC_INFORMATION info;
        for (SIZE_T address = 0; VirtualQueryEx(phandle, (LPVOID)address, &info, sizeof(info)); address += info.RegionSize) {
            if (info.State != MEM_COMMIT || info.RegionSize > 100 * 1024 * 1024) continue;

            std::vector<char> buffer(info.RegionSize);
            SIZE_T bytesRead;
            if (!ReadProcessMemory(phandle, (LPVOID)address, buffer.data(), info.RegionSize, &bytesRead)) continue;

            std::string memory(buffer.begin(), buffer.begin() + bytesRead);

            // Drive letter paths
            for (size_t pos = 0; (pos = memory.find(":\\", pos + 1)) != std::string::npos; ) {
                if (pos < 1 || !isalpha(memory[pos - 1])) continue;

                std::string path;
                path.push_back(memory[pos - 1]);
                path += ":\\";

                __int64 endPos = pos + 2;
                while (endPos < memory.size() &&
                    (isalnum(memory[endPos]) || memory[endPos] == '\\' || memory[endPos] == '/' ||
                        memory[endPos] == '.' || memory[endPos] == '_' || memory[endPos] == '-' ||
                        memory[endPos] == ' ' || memory[endPos] == '(' || memory[endPos] == ')')) {
                    path.push_back(memory[endPos]);
                    endPos++;
                }

                while (!path.empty() && (path.back() == ' ' || path.back() == '"')) {
                    path.pop_back();
                }

                if (path.length() > 5 && path.find('.') != std::string::npos) {
                    std::string ext = path.substr(path.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".exe" || ext == ".dll" || ext == ".sys" ||
                        ext == ".cmd" || ext == ".bat" || ext == ".ps1" ||
                        ext == ".msi" || ext == ".com") {
                        uniquePaths.insert(path);
                    }
                }
            }

            // Device paths
            for (__int64 pos = 0; (pos = memory.find("\\Device\\HarddiskVolume", pos)) != std::string::npos; pos++) {
                __int64 endPos = pos + 1;
                while (endPos < memory.size() &&
                    (isalnum(memory[endPos]) || memory[endPos] == '\\' || memory[endPos] == '/' ||
                        memory[endPos] == '.' || memory[endPos] == '_' || memory[endPos] == '-' ||
                        memory[endPos] == ' ' || memory[endPos] == '(' || memory[endPos] == ')')) {
                    endPos++;
                }

                std::string devicePath = memory.substr(pos, endPos - pos);
                std::string convertedPath = ConvertDevicePathToDriveLetter(devicePath);

                if (convertedPath != devicePath && convertedPath.length() > 3) {
                    std::string ext = convertedPath.substr(convertedPath.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".exe" || ext == ".dll" || ext == ".sys" ||
                        ext == ".cmd" || ext == ".bat" || ext == ".ps1" ||
                        ext == ".msi" || ext == ".com") {
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

        csvFile << "Time,File Name,File Path,Signature Status,File Exists,Source Process,Source PID\n";
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
                        info.sourceProcess = service;
                        info.sourcePID = pid;
                        allFileInfo.push_back(info);
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
                        info.sourceProcess = displayName;
                        info.sourcePID = pid;
                        allFileInfo.push_back(info);
                    }
                }
            }
        }

        // Generate CSV filename with timestamp
        std::string filename = "ProcessMemoryScan_";
        time_t now = time(nullptr);
        tm tm;
        localtime_s(&tm, &now);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm);
        filename += timeStr;
        filename += ".csv";

        ExportToCSV(allFileInfo, filename);
        return allFileInfo;
    }
}