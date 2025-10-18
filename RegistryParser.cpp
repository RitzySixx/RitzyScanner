#include "RegistryParser.h"
#include "EnhancedLogger.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <shlobj.h>
#include <sddl.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <mscat.h>
#include <SoftPub.h>
#include <algorithm>
#include <map>
#include <vector>
#include <set>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

namespace RegistryParser {
    void SetConsoleColor(WORD color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void ResetConsoleColor() {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    bool IsRunAsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(adminGroup);
        }
        return isAdmin == TRUE;
    }

    std::string SidToUsername(const std::string& sidStr) {
        PSID sid = NULL;
        if (!ConvertStringSidToSidA(sidStr.c_str(), &sid)) {
            return "";
        }

        CHAR name[256];
        CHAR domain[256];
        DWORD nameSize = 256;
        DWORD domainSize = 256;
        SID_NAME_USE sidType;

        std::string result;
        if (LookupAccountSidA(NULL, sid, name, &nameSize, domain, &domainSize, &sidType)) {
            result = std::string(domain) + "\\" + std::string(name);
        }
        else {
            result = "";
        }

        LocalFree(sid);
        return result;
    }

    std::string BytesToHex(const BYTE* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<unsigned>(data[i]);
        }
        return ss.str();
    }

    std::string FileTimeToString(FILETIME ft) {
        FILETIME localFt;
        FileTimeToLocalFileTime(&ft, &localFt);

        SYSTEMTIME st;
        FileTimeToSystemTime(&localFt, &st);

        char buffer[256];
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

        return std::string(buffer);
    }

    std::string CheckFileSignature(const std::string& filePath) {
        return EnhancedLogger::CheckFileSignatureUnified(filePath);
    }

    std::string IsSignatureTrusted(std::string& signature, const std::string& filePath) {
        return EnhancedLogger::CheckFileTrustUnified(filePath, signature);
    }

    std::string GetFileModificationTime(const std::string& filePath) {
        if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return "";
        }

        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            return FileTimeToString(fileInfo.ftLastWriteTime);
        }
        return "";
    }

    std::string CleanMuiCachePath(const std::string& path) {
        size_t pos = path.find(".ApplicationCompany");
        if (pos != std::string::npos) {
            return path.substr(0, pos);
        }
        pos = path.find(".FriendlyAppName");
        if (pos != std::string::npos) {
            return path.substr(0, pos);
        }
        return path;
    }

    std::vector<RegistryEntry> ParseCompatibilityAssistant() {
        std::vector<RegistryEntry> entries;
        const std::string keyPath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store";

        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "Scanning: HKCU\\" << keyPath << std::endl;
        ResetConsoleColor();

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return entries;
        }

        DWORD valueCount;
        DWORD maxValueNameLen;
        DWORD maxValueLen;
        if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valueCount, &maxValueNameLen, &maxValueLen, NULL, NULL) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return entries;
        }

        maxValueNameLen++;
        std::vector<CHAR> valueName(maxValueNameLen);
        std::vector<BYTE> valueData(maxValueLen);

        for (DWORD i = 0; i < valueCount; i++) {
            DWORD valueNameSize = maxValueNameLen;
            DWORD valueType;
            DWORD valueDataSize = maxValueLen;
            if (RegEnumValueA(hKey, i, valueName.data(), &valueNameSize, NULL, &valueType, valueData.data(), &valueDataSize) != ERROR_SUCCESS) {
                continue;
            }

            std::string path(valueName.data());

            std::string signature = CheckFileSignature(path);
            std::string trusted;
            if (signature == "Deleted") {
                trusted = ""; // deleted file, leave blank
            }
            else if (signature == "Invalid") {
                trusted = "Untrusted"; // unsigned or bad signature
            }
            else {
                trusted = IsSignatureTrusted(signature, path); // signed file, check trust
            }
            std::string modTime = GetFileModificationTime(path);

            entries.push_back({
                "", // execution time not available
                modTime,
                path.substr(path.find_last_of('\\') + 1),
                path,
                signature,
                trusted, // <-- ADDED
                "Current User",
                "",
                "HKCU\\" + keyPath,
                "CompatibilityAssistant"
                });

            // Enhanced logging for problematic entries
            if (EnhancedLogger::IsProblematicEntry(signature, trusted)) {
                std::string issueType;
                if (signature == "Deleted") {
                    issueType = "DELETED";
                } else if (signature == "Invalid" || trusted == "Untrusted") {
                    issueType = "INVALID_SIGNATURE";
                } else if (trusted == "Unsigned") {
                    issueType = "UNSIGNED";
                } else {
                    issueType = "UNTRUSTED";
                }

                if (!EnhancedLogger::IsDuplicateEntry(path, issueType)) {
                    DetailedLogEntry logEntry = {};
                    logEntry.timestamp = EnhancedLogger::GetCurrentTimestamp();
                    logEntry.scanType = "Registry";
                    logEntry.source = "CompatibilityAssistant";
                    logEntry.filePath = path;
                    logEntry.issueType = issueType;
                    logEntry.signatureStatus = signature;
                    logEntry.trustedStatus = trusted;
                    logEntry.fileSize = (signature != "Deleted") ? EnhancedLogger::GetFileSize(path) : "N/A";
                    logEntry.modificationTime = modTime;
                    logEntry.md5Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "MD5") : "N/A";
                    logEntry.sha256Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "SHA256") : "N/A";
                    logEntry.additionalInfo = (signature != "Deleted") ? EnhancedLogger::GetDetailedFileInfo(path) : "File Deleted";
                    logEntry.fileExists = (signature != "Deleted");
                    logEntry.sourcePID = 0;

                    EnhancedLogger::LogProblematicEntry(logEntry);
                    EnhancedLogger::AddToGlobalTracking(path, issueType);
                }
            }
        }

        RegCloseKey(hKey);
        return entries;
    }

    std::vector<RegistryEntry> ParseMuiCache(const std::string& keyPath) {
        std::vector<RegistryEntry> entries;

        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "Scanning: HKCU\\" << keyPath << std::endl;
        ResetConsoleColor();

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return entries;
        }

        DWORD valueCount;
        DWORD maxValueNameLen;
        DWORD maxValueLen;
        if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valueCount, &maxValueNameLen, &maxValueLen, NULL, NULL) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return entries;
        }

        maxValueNameLen++;
        std::vector<CHAR> valueName(maxValueNameLen);
        std::vector<BYTE> valueData(maxValueLen);

        for (DWORD i = 0; i < valueCount; i++) {
            DWORD valueNameSize = maxValueNameLen;
            DWORD valueType;
            DWORD valueDataSize = maxValueLen;
            if (RegEnumValueA(hKey, i, valueName.data(), &valueNameSize, NULL, &valueType, valueData.data(), &valueDataSize) != ERROR_SUCCESS) {
                continue;
            }

            std::string path = CleanMuiCachePath(valueName.data());

            std::string signature = CheckFileSignature(path);
            std::string trusted;
            if (signature == "Deleted") {
                trusted = ""; // deleted file, leave blank
            }
            else if (signature == "Invalid") {
                trusted = "Untrusted"; // unsigned or bad signature
            }
            else {
                trusted = IsSignatureTrusted(signature, path); // signed file, check trust
            }
            std::string modTime = GetFileModificationTime(path);

            entries.push_back({
                "", // execution time not available
                modTime,
                path.substr(path.find_last_of('\\') + 1),
                path,
                signature,
                trusted, // <-- ADDED
                "Current User",
                "",
                "HKCU\\" + keyPath,
                "MuiCache"
                });

            // Enhanced logging for problematic entries
            if (EnhancedLogger::IsProblematicEntry(signature, trusted)) {
                std::string issueType;
                if (signature == "Deleted") {
                    issueType = "DELETED";
                } else if (signature == "Invalid" || trusted == "Untrusted") {
                    issueType = "INVALID_SIGNATURE";
                } else if (trusted == "Unsigned") {
                    issueType = "UNSIGNED";
                } else {
                    issueType = "UNTRUSTED";
                }

                if (!EnhancedLogger::IsDuplicateEntry(path, issueType)) {
                    DetailedLogEntry logEntry = {};
                    logEntry.timestamp = EnhancedLogger::GetCurrentTimestamp();
                    logEntry.scanType = "Registry";
                    logEntry.source = "MuiCache";
                    logEntry.filePath = path;
                    logEntry.issueType = issueType;
                    logEntry.signatureStatus = signature;
                    logEntry.trustedStatus = trusted;
                    logEntry.fileSize = (signature != "Deleted") ? EnhancedLogger::GetFileSize(path) : "N/A";
                    logEntry.modificationTime = modTime;
                    logEntry.md5Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "MD5") : "N/A";
                    logEntry.sha256Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "SHA256") : "N/A";
                    logEntry.additionalInfo = (signature != "Deleted") ? EnhancedLogger::GetDetailedFileInfo(path) : "File Deleted";
                    logEntry.fileExists = (signature != "Deleted");
                    logEntry.sourcePID = 0;

                    EnhancedLogger::LogProblematicEntry(logEntry);
                    EnhancedLogger::AddToGlobalTracking(path, issueType);
                }
            }
        }

        RegCloseKey(hKey);
        return entries;
    }

    std::vector<RegistryEntry> ParseBAMKeys() {
        std::vector<RegistryEntry> entries;
        std::vector<std::string> bamPaths = {
            "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
            "SYSTEM\\CurrentControlSet\\Services\\bam\\state\\UserSettings"
        };

        for (const auto& bamPath : bamPaths) {
            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << "Scanning: HKLM\\" << bamPath << std::endl;
            ResetConsoleColor();

            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, bamPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subKeyCount;
            DWORD maxSubKeyLen;
            if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subKeyCount, &maxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                continue;
            }

            maxSubKeyLen++;
            std::vector<CHAR> subKeyName(maxSubKeyLen);

            for (DWORD i = 0; i < subKeyCount; i++) {
                DWORD subKeyNameSize = maxSubKeyLen;
                if (RegEnumKeyExA(hKey, i, subKeyName.data(), &subKeyNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                    continue;
                }

                std::string sid(subKeyName.data());
                std::string user = SidToUsername(sid);

                HKEY hSubKey;
                std::string subKeyPath = bamPath + "\\" + sid;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) {
                    continue;
                }

                DWORD valueCount;
                DWORD maxValueNameLen;
                DWORD maxValueLen;
                if (RegQueryInfoKeyA(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, &valueCount, &maxValueNameLen, &maxValueLen, NULL, NULL) != ERROR_SUCCESS) {
                    RegCloseKey(hSubKey);
                    continue;
                }

                maxValueNameLen++;
                std::vector<CHAR> valueName(maxValueNameLen);
                std::vector<BYTE> valueData(maxValueLen);

                for (DWORD j = 0; j < valueCount; j++) {
                    DWORD valueNameSize = maxValueNameLen;
                    DWORD valueType;
                    DWORD valueDataSize = maxValueLen;
                    if (RegEnumValueA(hSubKey, j, valueName.data(), &valueNameSize, NULL, &valueType, valueData.data(), &valueDataSize) != ERROR_SUCCESS) {
                        continue;
                    }

                    if (valueType == REG_BINARY && valueDataSize == 24) {
                        ULONGLONG timestamp = *reinterpret_cast<ULONGLONG*>(valueData.data());
                        FILETIME ft;
                        ft.dwLowDateTime = static_cast<DWORD>(timestamp & 0xFFFFFFFF);
                        ft.dwHighDateTime = static_cast<DWORD>(timestamp >> 32);

                        std::string executionTime = FileTimeToString(ft);
                        std::string pathName(valueName.data());
                        std::string application;
                        std::string path;
                        std::string signature;
                        std::string modTime;

                        if (pathName.find("\\Device\\HarddiskVolume") == 0) {
                            size_t lastSlash = pathName.find_last_of('\\');
                            if (lastSlash != std::string::npos) {
                                application = pathName.substr(lastSlash + 1);
                                path = "C:" + pathName.substr(pathName.find('\\', 23));
                                signature = CheckFileSignature(path);
                                modTime = GetFileModificationTime(path);
                            }
                        }
                        else {
                            application = pathName;
                            path = pathName;
                            signature = CheckFileSignature(path);
                            modTime = GetFileModificationTime(path);
                        }

                        std::string trusted;
                        if (signature == "Deleted") {
                            trusted = ""; // deleted file, leave blank
                        }
                        else if (signature == "Invalid") {
                            trusted = "Untrusted"; // unsigned or bad signature
                        }
                        else {
                            trusted = IsSignatureTrusted(signature, path); // signed file, check trust
                        }

                        entries.push_back({
                            executionTime,
                            modTime,
                            application,
                            path,
                            signature,
                            trusted, // <-- ADDED
                            user,
                            sid,
                            "HKLM\\" + bamPath,
                            "BAM"
                            });

                        // Enhanced logging for problematic entries
                        if (EnhancedLogger::IsProblematicEntry(signature, trusted)) {
                            std::string issueType;
                            if (signature == "Deleted") {
                                issueType = "DELETED";
                            } else if (signature == "Invalid" || trusted == "Untrusted") {
                                issueType = "INVALID_SIGNATURE";
                            } else if (trusted == "Unsigned") {
                                issueType = "UNSIGNED";
                            } else {
                                issueType = "UNTRUSTED";
                            }

                            if (!EnhancedLogger::IsDuplicateEntry(path, issueType)) {
                                DetailedLogEntry logEntry = {};
                                logEntry.timestamp = EnhancedLogger::GetCurrentTimestamp();
                                logEntry.scanType = "Registry";
                                logEntry.source = "BAM";
                                logEntry.filePath = path;
                                logEntry.issueType = issueType;
                                logEntry.signatureStatus = signature;
                                logEntry.trustedStatus = trusted;
                                logEntry.fileSize = (signature != "Deleted") ? EnhancedLogger::GetFileSize(path) : "N/A";
                                logEntry.modificationTime = modTime;
                                logEntry.md5Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "MD5") : "N/A";
                                logEntry.sha256Hash = (signature != "Deleted") ? EnhancedLogger::CalculateFileHash(path, "SHA256") : "N/A";
                                logEntry.additionalInfo = (signature != "Deleted") ? EnhancedLogger::GetDetailedFileInfo(path) : "File Deleted";
                                logEntry.fileExists = (signature != "Deleted");
                                logEntry.sourcePID = 0;

                                EnhancedLogger::LogProblematicEntry(logEntry);
                                EnhancedLogger::AddToGlobalTracking(path, issueType);
                            }
                        }
                    }
                }

                RegCloseKey(hSubKey);
            }

            RegCloseKey(hKey);
        }

        return entries;
    }

    void ExportToCSV(const std::vector<RegistryEntry>& entries, const std::string& filename) {
        // Existing code unchanged, but improved with better escaping
        std::ofstream csvFile(filename);
        if (!csvFile.is_open()) {
            std::cerr << "Failed to create CSV file: " << filename << std::endl;
            return;
        }

        csvFile << "ExecutionTime,ModificationTime,Application,Path,Signature,Trusted,User,SID,RegistryPath,RegistryType\n";

        for (const auto& entry : entries) {
            std::string escapePath = entry.path;
            size_t pos = 0;
            while ((pos = escapePath.find('"', pos)) != std::string::npos) {
                escapePath.replace(pos, 1, "\"\"");
                pos += 2;
            }

            csvFile << "\"" << entry.executionTime << "\","
                << "\"" << entry.modificationTime << "\","
                << "\"" << entry.application << "\","
                << "\"" << escapePath << "\","
                << "\"" << entry.signature << "\","
                << "\"" << entry.trusted << "\","
                << "\"" << entry.user << "\","
                << "\"" << entry.sid << "\","
                << "\"" << entry.regPath << "\","
                << "\"" << entry.regType << "\"\n";
        }

        csvFile.close();
        std::cout << "Exported " << entries.size() << " entries to " << filename << std::endl;
    }

    std::vector<RegistryEntry> ParseAllRegistry() {
        std::vector<RegistryEntry> entries;

        if (!IsRunAsAdmin()) {
            SetConsoleColor(FOREGROUND_RED);
            std::cout << "Registry parsing requires admin privileges." << std::endl;
            ResetConsoleColor();
            return entries;
        }

        // Parse all entries
        auto bamEntries = ParseBAMKeys();
        auto compatEntries = ParseCompatibilityAssistant();
        auto muiCacheEntries = ParseMuiCache("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
        auto shellNoRoamEntries = ParseMuiCache("Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache");

        // Combine all entries
        std::vector<RegistryEntry> allEntries;
        allEntries.insert(allEntries.end(), bamEntries.begin(), bamEntries.end());
        allEntries.insert(allEntries.end(), compatEntries.begin(), compatEntries.end());
        allEntries.insert(allEntries.end(), muiCacheEntries.begin(), muiCacheEntries.end());
        allEntries.insert(allEntries.end(), shellNoRoamEntries.begin(), shellNoRoamEntries.end());

        // Deduplicate by path
        std::set<std::string> seenPaths;
        std::vector<RegistryEntry> uniqueEntries;
        for (const auto& entry : allEntries) {
            if (seenPaths.find(entry.path) == seenPaths.end()) {
                seenPaths.insert(entry.path);
                uniqueEntries.push_back(entry);
            }
        }

        // Export to combined CSV
        ExportToCSV(uniqueEntries, "Registry.csv");

        return entries;
    }
}