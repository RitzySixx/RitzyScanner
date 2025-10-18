// EnhancedLogger.h
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <winhttp.h>
#include <chrono>

struct DetailedLogEntry {
    std::string timestamp;
    std::string scanType;
    std::string source;
    std::string filePath;
    std::string issueType; // "UNSIGNED", "DELETED", "INVALID_SIGNATURE", "UNTRUSTED"
    std::string signatureStatus;
    std::string trustedStatus;
    std::string fileSize;
    std::string modificationTime;
    std::string md5Hash;
    std::string sha256Hash;
    std::string additionalInfo;
    bool fileExists;
    DWORD sourcePID;
};

namespace EnhancedLogger {
    void SetConsoleColor(WORD color);
    void ResetConsoleColor();
    std::string GetCurrentTimestamp();
    std::string CalculateFileHash(const std::string& filePath, const std::string& hashType);
    std::string GetFileSize(const std::string& filePath);
    std::string GetDetailedFileInfo(const std::string& filePath);
    bool IsProblematicEntry(const std::string& signatureStatus, const std::string& trustedStatus);
    void LogProblematicEntry(const DetailedLogEntry& entry);
    void CollectProblematicEntry(const DetailedLogEntry& entry);
    void ExportDetailedLogToCSV(const std::vector<DetailedLogEntry>& entries, const std::string& filename);
    void ExportDetailedLogToTXT(const std::vector<DetailedLogEntry>& entries, const std::string& filename);
    void InitializeGlobalTracking();
    bool IsDuplicateEntry(const std::string& filePath, const std::string& issueType);
    void AddToGlobalTracking(const std::string& filePath, const std::string& issueType);

    // Simplified signature checking - only Valid or Invalid

    // Simplified Signature Checking - Consistent Results
    std::string CheckFileSignatureUnified(const std::string& filePath);
    std::string CheckFileTrustUnified(const std::string& filePath, std::string& signatureStatus);
}