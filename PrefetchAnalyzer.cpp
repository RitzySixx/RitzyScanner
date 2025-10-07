#include "PrefetchAnalyzer.h"
#include <iostream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <wincrypt.h>
#include <shlwapi.h>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

PrefetchAnalyzer::PrefetchAnalyzer() {}

PrefetchAnalyzer::~PrefetchAnalyzer() {}

bool PrefetchAnalyzer::CheckAdminPrivileges() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

int PrefetchAnalyzer::CheckPrefetchRegistrySetting() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegGetValueA(hKey, NULL, "EnablePrefetcher", RRF_RT_REG_DWORD, NULL, &value, &size);
        RegCloseKey(hKey);
    }
    return value;
}

std::vector<unsigned char> PrefetchAnalyzer::DecompressPrefetchFile(const std::vector<unsigned char>& data) {
    if (data.size() < 8) return {};

    uint32_t signature = *reinterpret_cast<const uint32_t*>(&data[0]);
    uint32_t decompressedSize = *reinterpret_cast<const uint32_t*>(&data[4]);

    if ((signature & 0x00FFFFFF) != 0x004D414D) return {};

    std::vector<unsigned char> compressedData(data.begin() + 8, data.end());

    // For simplicity, try to decompress using Inflate if zlib was available
    // Since zlib.h is not included, return compressedData as fallback
    // In a real implementation, link zlib and use inflate
    return compressedData; // Placeholder
}

std::string PrefetchAnalyzer::GetPrefetchExecutableName(const std::string& filePath, const std::vector<unsigned char>& data) {
    if (data.size() < 0x10 + 64) return "";

    std::vector<unsigned char> buffer(64);
    std::copy(data.begin() + 0x10, data.begin() + 0x10 + 64, buffer.begin());

    std::string exeName(reinterpret_cast<char*>(&buffer[0]), 64);
    exeName.erase(exeName.find_last_not_of('\0') + 1);

    // Validate name
    if (exeName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. ()@+#") == std::string::npos && !exeName.empty()) {
        return exeName;
    }
    return "";
}

std::string PrefetchAnalyzer::CalculateSHA256(const std::string& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "";
    }

    BYTE buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }

    BYTE hash[32];
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return ss.str();
}

void PrefetchAnalyzer::CheckForDeletedPrefetchFiles() {
    HANDLE hVolume = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) return;

    USN_JOURNAL_DATA journalData;
    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &bytesReturned, NULL)) {
        CloseHandle(hVolume);
        return;
    }

    READ_USN_JOURNAL_DATA readData = {0};
    readData.StartUsn = journalData.FirstUsn;
    readData.ReasonMask = USN_REASON_FILE_DELETE;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = journalData.UsnJournalID;

    const DWORD bufferSize = 65536;
    PVOID buffer = malloc(bufferSize);
    if (!buffer) {
        CloseHandle(hVolume);
        return;
    }

    int deletedCount = 0;
    while (DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData), buffer, bufferSize, &bytesReturned, NULL)) {
        PUSN_RECORD usnRecord = (PUSN_RECORD)((PCHAR)buffer + sizeof(USN));
        while ((PCHAR)usnRecord < (PCHAR)buffer + bytesReturned) {
            if (usnRecord->Reason & USN_REASON_FILE_DELETE) {
                std::wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));
                if (fileName.size() > 3 && fileName.substr(fileName.size() - 3) == L".pf") {
                    deletedCount++;
                }
            }
            usnRecord = (PUSN_RECORD)((PCHAR)usnRecord + usnRecord->RecordLength);
        }
        readData.StartUsn = *(USN*)buffer;
        if (bytesReturned <= sizeof(USN)) break;
    }

    free(buffer);
    CloseHandle(hVolume);

    if (deletedCount > 0) {
        detectedIssues.push_back({"Deleted Prefetch Files", "Found " + std::to_string(deletedCount) + " deleted .pf files in journal"});
    }
}

void PrefetchAnalyzer::ProcessFile(const std::string& filePath) {
    std::string fileName = std::filesystem::path(filePath).filename().string();
    std::string exeName = "";
    std::string details = "";
    bool isSuspicious = false;

    try {
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (!GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            details = "Cannot access file attributes";
            isSuspicious = true;
        } else {
            if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                details = "File is read-only";
                isSuspicious = true;
            }
            if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
                details += (details.empty() ? "" : "; ") + std::string("Hidden prefetch file");
                isSuspicious = true;
            }
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            details += (details.empty() ? "" : "; ") + std::string("Cannot read file");
            isSuspicious = true;
        } else {
            std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            std::string signature(fileContent.begin(), fileContent.begin() + 3);
            bool isCompressed = (signature == "MAM");
            std::vector<unsigned char> data = fileContent;

            if (isCompressed) {
                auto decompressed = DecompressPrefetchFile(fileContent);
                if (!decompressed.empty()) {
                    data = decompressed;
                }
            }

            exeName = GetPrefetchExecutableName(filePath, data);
            if (exeName.empty()) {
                std::string baseName = std::filesystem::path(filePath).stem().string();
                size_t dashPos = baseName.find('-');
                if (dashPos != std::string::npos) {
                    baseName = baseName.substr(0, dashPos);
                }
                exeName = baseName;
            }

            if (exeName == "Unknown") {
                details += (details.empty() ? "" : "; ") + std::string("Invalid or unreadable process name");
                isSuspicious = true;
            }

            std::string sha256 = CalculateSHA256(filePath);


            std::lock_guard<std::mutex> lock(mtx);
            if (sha256 != "") {
                hashTable[sha256].push_back(fileName);
            }

            if (isSuspicious) {
                suspiciousFiles[fileName] = details + " (Process: " + exeName + ")";
            }
        }
    } catch (const std::exception& e) {
        details += (details.empty() ? "" : "; ") + std::string("Error processing file: ") + e.what();
        isSuspicious = true;
        std::lock_guard<std::mutex> lock(mtx);
        suspiciousFiles[fileName] = details + " (Process: " + exeName + ")";
    }
}

void PrefetchAnalyzer::AnalyzePrefetchFiles(const std::string& directory) {
    std::vector<std::thread> threads;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() == ".pf") {
            threads.emplace_back(&PrefetchAnalyzer::ProcessFile, this, entry.path().string());
        }
    }

    for (auto& t : threads) {
        t.join();
    }

    // Check for deleted prefetch files in USN journal
    CheckForDeletedPrefetchFiles();

    // Detect repeated hashes
    for (const auto& pair : hashTable) {
        if (pair.second.size() > 1) {
            for (const auto& file : pair.second) {
                if (suspiciousFiles.find(file) == suspiciousFiles.end()) {
                    suspiciousFiles[file] = file + " was modified with type or echo";
                } else {
                    suspiciousFiles[file] += "; " + file + " was modified with type or echo";
                }
            }
        }
    }

    // Add prefetch setting issue if not optimal
    int prefetchValue = CheckPrefetchRegistrySetting();
    if (prefetchValue != 3) {
        std::string issueDetails;
        switch (prefetchValue) {
            case 0: issueDetails = "Prefetch is DISABLED (value: 0)"; break;
            case 1: issueDetails = "Prefetch is ENABLED (value: 1 - Application launch only)"; break;
            case 2: issueDetails = "Prefetch is DISABLED for Applications (value: 2 - Boot only)"; break;
            default: issueDetails = "Unknown Prefetch setting (value: " + std::to_string(prefetchValue) + ")"; break;
        }
        detectedIssues.push_back({"Prefetch Setting", issueDetails});
    }

    // Add suspicious files as issues
    for (const auto& pair : suspiciousFiles) {
        detectedIssues.push_back({"Suspicious File", pair.first + " : " + pair.second});
    }

    // If no issues, add clean message
    if (detectedIssues.empty()) {
        detectedIssues.push_back({"Status", "Prefetch Folder is clean."});
    }
}

void PrefetchAnalyzer::LogToCSV(const std::string& csvPath) {
    std::ofstream csvFile(csvPath);
    if (!csvFile) return;

    csvFile << "Issue,Details\n";
    for (const auto& issue : detectedIssues) {
        csvFile << issue.issueType << "," << issue.details << "\n";
    }
    csvFile.close();
}