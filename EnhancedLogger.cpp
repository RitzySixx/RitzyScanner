// EnhancedLogger.cpp
#include "EnhancedLogger.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

namespace EnhancedLogger {
    std::set<std::string> globalTrackingSet;
    std::map<std::string, std::set<std::string>> globalPathIssueTracking;

    void SetConsoleColor(WORD color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void ResetConsoleColor() {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string CalculateFileHash(const std::string& filePath, const std::string& hashType) {
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return "N/A";
        }

        DWORD hashAlgorithm = 0;
        if (hashType == "MD5") {
            hashAlgorithm = CALG_MD5;
        } else if (hashType == "SHA256") {
            hashAlgorithm = CALG_SHA_256;
        } else {
            CloseHandle(hFile);
            return "N/A";
        }

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return "N/A";
        }

        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, hashAlgorithm, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "N/A";
        }

        const size_t bufferSize = 8192;
        std::vector<BYTE> buffer(bufferSize);
        DWORD bytesRead = 0;
        BOOL result = ReadFile(hFile, buffer.data(), bufferSize, &bytesRead, NULL);

        while (result && bytesRead > 0) {
            if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return "N/A";
            }
            result = ReadFile(hFile, buffer.data(), bufferSize, &bytesRead, NULL);
        }

        DWORD hashSize = 0;
        DWORD paramSize = sizeof(DWORD);
        if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &paramSize, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "N/A";
        }

        std::vector<BYTE> hash(hashSize);
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashSize, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "N/A";
        }

        // Convert hash to hex string
        std::ostringstream oss;
        for (DWORD i = 0; i < hashSize; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        return oss.str();
    }

    std::string GetFileSize(const std::string& filePath) {
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return "N/A";
        }

        LARGE_INTEGER fileSize;
        if (GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            std::ostringstream oss;
            oss << fileSize.QuadPart << " bytes";
            return oss.str();
        }

        CloseHandle(hFile);
        return "N/A";
    }

    std::string GetDetailedFileInfo(const std::string& filePath) {
        std::ostringstream oss;

        // Get file attributes
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            oss << "Attributes: ";
            if (attributes & FILE_ATTRIBUTE_READONLY) oss << "ReadOnly ";
            if (attributes & FILE_ATTRIBUTE_HIDDEN) oss << "Hidden ";
            if (attributes & FILE_ATTRIBUTE_SYSTEM) oss << "System ";
            if (attributes & FILE_ATTRIBUTE_DIRECTORY) oss << "Directory ";
            if (attributes & FILE_ATTRIBUTE_ARCHIVE) oss << "Archive ";
            if (attributes & FILE_ATTRIBUTE_COMPRESSED) oss << "Compressed ";
            if (attributes & FILE_ATTRIBUTE_ENCRYPTED) oss << "Encrypted ";
        }

        // Get file version info if available
        DWORD versionSize = GetFileVersionInfoSizeA(filePath.c_str(), NULL);
        if (versionSize > 0) {
            std::vector<BYTE> versionData(versionSize);
            if (GetFileVersionInfoA(filePath.c_str(), 0, versionSize, versionData.data())) {
                VS_FIXEDFILEINFO* fileInfo = NULL;
                UINT len = 0;
                if (VerQueryValueA(versionData.data(), "\\", (LPVOID*)&fileInfo, &len)) {
                    oss << "| Version: " << HIWORD(fileInfo->dwFileVersionMS) << "."
                        << LOWORD(fileInfo->dwFileVersionMS) << "."
                        << HIWORD(fileInfo->dwFileVersionLS) << "."
                        << LOWORD(fileInfo->dwFileVersionLS);
                }
            }
        }

        return oss.str();
    }

    bool IsProblematicEntry(const std::string& signatureStatus, const std::string& trustedStatus) {
        // Check for deleted files
        if (signatureStatus == "Deleted" || signatureStatus == "DELETED") {
            return true;
        }

        // Check for unsigned files
        if (signatureStatus == "Unsigned" || signatureStatus == "Invalid") {
            return true;
        }

        // Check for untrusted files
        if (trustedStatus == "Untrusted" || trustedStatus == "Unsigned") {
            return true;
        }

        return false;
    }

    void LogProblematicEntry(const DetailedLogEntry& entry) {
        // Send to SentryX server first
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[SENTRYX] Sending problematic entry to remote server..." << std::endl;
        ResetConsoleColor();

        if (SendToSentryX(entry)) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "[SENTRYX] Successfully sent to remote server" << std::endl;
            ResetConsoleColor();
        } else {
            SetConsoleColor(FOREGROUND_RED);
            std::cout << "[SENTRYX] Failed to send to remote server" << std::endl;
            ResetConsoleColor();
        }

        // Console output with colors
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "\n=== PROBLEMATIC ENTRY DETECTED ===" << std::endl;
        ResetConsoleColor();

        std::cout << "Timestamp: " << entry.timestamp << std::endl;
        std::cout << "Scan Type: " << entry.scanType << std::endl;
        std::cout << "Source: " << entry.source << std::endl;

        SetConsoleColor(FOREGROUND_RED);
        std::cout << "ISSUE: " << entry.issueType << std::endl;
        ResetConsoleColor();

        std::cout << "File Path: " << entry.filePath << std::endl;
        std::cout << "Signature Status: " << entry.signatureStatus << std::endl;
        std::cout << "Trusted Status: " << entry.trustedStatus << std::endl;

        if (entry.fileExists) {
            std::cout << "File Size: " << entry.fileSize << std::endl;
            std::cout << "Modification Time: " << entry.modificationTime << std::endl;
            std::cout << "MD5 Hash: " << entry.md5Hash << std::endl;
            std::cout << "SHA256 Hash: " << entry.sha256Hash << std::endl;
            std::cout << "Additional Info: " << entry.additionalInfo << std::endl;
        }

        if (entry.sourcePID != 0) {
            std::cout << "Source PID: " << entry.sourcePID << std::endl;
        }

        std::cout << "=====================================" << std::endl;
    }

    void ExportDetailedLogToCSV(const std::vector<DetailedLogEntry>& entries, const std::string& filename) {
        std::ofstream csvFile(filename);
        if (!csvFile.is_open()) {
            std::cerr << "Failed to create detailed log CSV file: " << filename << std::endl;
            return;
        }

        csvFile << "Timestamp,ScanType,Source,FilePath,IssueType,SignatureStatus,TrustedStatus,FileSize,ModificationTime,MD5Hash,SHA256Hash,AdditionalInfo,FileExists,SourcePID\n";

        for (const auto& entry : entries) {
            // Escape quotes in strings
            auto escapeString = [](std::string str) -> std::string {
                size_t pos = 0;
                while ((pos = str.find('"', pos)) != std::string::npos) {
                    str.replace(pos, 1, "\"\"");
                    pos += 2;
                }
                return str;
            };

            csvFile << "\"" << escapeString(entry.timestamp) << "\","
                << "\"" << escapeString(entry.scanType) << "\","
                << "\"" << escapeString(entry.source) << "\","
                << "\"" << escapeString(entry.filePath) << "\","
                << "\"" << escapeString(entry.issueType) << "\","
                << "\"" << escapeString(entry.signatureStatus) << "\","
                << "\"" << escapeString(entry.trustedStatus) << "\","
                << "\"" << escapeString(entry.fileSize) << "\","
                << "\"" << escapeString(entry.modificationTime) << "\","
                << "\"" << escapeString(entry.md5Hash) << "\","
                << "\"" << escapeString(entry.sha256Hash) << "\","
                << "\"" << escapeString(entry.additionalInfo) << "\","
                << "\"" << (entry.fileExists ? "Yes" : "No") << "\","
                << "\"" << entry.sourcePID << "\"\n";
        }

        csvFile.close();
        std::cout << "Exported " << entries.size() << " problematic entries to " << filename << std::endl;
    }

    void ExportDetailedLogToTXT(const std::vector<DetailedLogEntry>& entries, const std::string& filename) {
        std::ofstream txtFile(filename);
        if (!txtFile.is_open()) {
            std::cerr << "Failed to create detailed log TXT file: " << filename << std::endl;
            return;
        }

        txtFile << "DETAILED FORENSIC ANALYSIS - PROBLEMATIC ENTRIES ONLY\n";
        txtFile << "Generated: " << GetCurrentTimestamp() << "\n";
        txtFile << "Total Problematic Entries: " << entries.size() << "\n";
        txtFile << "=============================================================\n\n";

        for (size_t i = 0; i < entries.size(); i++) {
            const auto& entry = entries[i];

            txtFile << "ENTRY #" << (i + 1) << "\n";
            txtFile << "-------------------------------------------------------------\n";
            txtFile << "Timestamp: " << entry.timestamp << "\n";
            txtFile << "Scan Type: " << entry.scanType << "\n";
            txtFile << "Source: " << entry.source << "\n";
            txtFile << "File Path: " << entry.filePath << "\n";
            txtFile << "Issue Type: " << entry.issueType << "\n";
            txtFile << "Signature Status: " << entry.signatureStatus << "\n";
            txtFile << "Trusted Status: " << entry.trustedStatus << "\n";

            if (entry.fileExists) {
                txtFile << "File Size: " << entry.fileSize << "\n";
                txtFile << "Modification Time: " << entry.modificationTime << "\n";
                txtFile << "MD5 Hash: " << entry.md5Hash << "\n";
                txtFile << "SHA256 Hash: " << entry.sha256Hash << "\n";
                txtFile << "Additional Info: " << entry.additionalInfo << "\n";
            } else {
                txtFile << "File Status: DELETED/MISSING\n";
            }

            if (entry.sourcePID != 0) {
                txtFile << "Source PID: " << entry.sourcePID << "\n";
            }

            txtFile << "\n";
        }

        txtFile.close();
        std::cout << "Exported detailed analysis to " << filename << std::endl;
    }

    void InitializeGlobalTracking() {
        globalTrackingSet.clear();
        globalPathIssueTracking.clear();
    }

    bool IsDuplicateEntry(const std::string& filePath, const std::string& issueType) {
        std::string key = filePath + "|" + issueType;
        return globalTrackingSet.find(key) != globalTrackingSet.end();
    }

    void AddToGlobalTracking(const std::string& filePath, const std::string& issueType) {
        std::string key = filePath + "|" + issueType;
        globalTrackingSet.insert(key);

        if (globalPathIssueTracking.find(filePath) == globalPathIssueTracking.end()) {
            globalPathIssueTracking[filePath] = std::set<std::string>();
        }
        globalPathIssueTracking[filePath].insert(issueType);
    }

    // SentryX Integration Functions
    bool SendToSentryX(const DetailedLogEntry& entry) {
        std::string payload = CreateSentryXPayload(entry);
        std::string url = "http://sentryx.drizzy.vip/api/13/logs";

        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-API-Key"] = "fw52GwXQcw3UtVdsI7mlRwIVfhErgQ6tkWSFgNdR1oc";

        return PerformHttpRequest(url, "POST", payload, headers);
    }

    std::string CreateSentryXPayload(const DetailedLogEntry& entry) {
        std::ostringstream json;

        json << "{";
        json << "\"type\":\"SentryScanner\",";
        json << "\"message\":\"Problematic file detected: " << entry.filePath << "\",";
        json << "\"data\":{";
        json << "\"timestamp\":\"" << entry.timestamp << "\",";
        json << "\"scanType\":\"" << entry.scanType << "\",";
        json << "\"source\":\"" << entry.source << "\",";
        json << "\"filePath\":\"" << entry.filePath << "\",";
        json << "\"issueType\":\"" << entry.issueType << "\",";
        json << "\"signatureStatus\":\"" << entry.signatureStatus << "\",";
        json << "\"trustedStatus\":\"" << entry.trustedStatus << "\",";
        json << "\"fileSize\":\"" << entry.fileSize << "\",";
        json << "\"modificationTime\":\"" << entry.modificationTime << "\",";
        json << "\"md5Hash\":\"" << entry.md5Hash << "\",";
        json << "\"sha256Hash\":\"" << entry.sha256Hash << "\",";
        json << "\"fileExists\":\"" << (entry.fileExists ? "true" : "false") << "\",";
        json << "\"sourcePID\":\"" << entry.sourcePID << "\",";
        json << "\"additionalInfo\":\"" << entry.additionalInfo << "\"";
        json << "}";
        json << "}";

        return json.str();
    }

    bool PerformHttpRequest(const std::string& url, const std::string& method, const std::string& data, const std::map<std::string, std::string>& headers) {
        // Parse URL
        std::string host, path;
        size_t hostStart = url.find("://");
        if (hostStart == std::string::npos) return false;

        hostStart += 3;
        size_t pathStart = url.find('/', hostStart);
        if (pathStart == std::string::npos) {
            host = url.substr(hostStart);
            path = "/";
        } else {
            host = url.substr(hostStart, pathStart - hostStart);
            path = url.substr(pathStart);
        }

        // Initialize WinHTTP
        HINTERNET hSession = WinHttpOpen(L"RitzyScanner/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, std::wstring(host.begin(), host.end()).c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, std::wstring(method.begin(), method.end()).c_str(),
            std::wstring(path.begin(), path.end()).c_str(), NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Add headers
        for (const auto& header : headers) {
            std::string headerStr = header.first + ": " + header.second;
            WinHttpAddRequestHeaders(hRequest, std::wstring(headerStr.begin(), headerStr.end()).c_str(),
                (DWORD)headerStr.length(), WINHTTP_ADDREQ_FLAG_ADD);
        }

        // Send request
        std::wstring wData(data.begin(), data.end());
        LPCWSTR pData = wData.c_str();
        DWORD dataLength = (DWORD)data.length() * sizeof(wchar_t);

        BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)pData, dataLength, dataLength, 0);

        if (result) {
            result = WinHttpReceiveResponse(hRequest, NULL);
        }

        // Cleanup
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return result == TRUE;
    }
}