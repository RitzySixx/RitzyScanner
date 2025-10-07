#ifndef PREFETCHANALYZER_H
#define PREFETCHANALYZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <fstream>
#include <windows.h>
#include <shlobj.h>
#include <winioctl.h>

struct DetectedIssue {
    std::string issueType;
    std::string details;
};

class PrefetchAnalyzer {
public:
    PrefetchAnalyzer();
    ~PrefetchAnalyzer();

    bool CheckAdminPrivileges();
    int CheckPrefetchRegistrySetting();
    void AnalyzePrefetchFiles(const std::string& directory);
    void LogToCSV(const std::string& csvPath);

private:
    std::vector<DetectedIssue> detectedIssues;
    std::unordered_map<std::string, std::vector<std::string>> hashTable;
    std::unordered_map<std::string, std::string> suspiciousFiles;
    std::mutex mtx;

    std::vector<unsigned char> DecompressPrefetchFile(const std::vector<unsigned char>& data);
    std::string GetPrefetchExecutableName(const std::string& filePath, const std::vector<unsigned char>& data);
    std::string CalculateSHA256(const std::string& filePath);
    void ProcessFile(const std::string& filePath);
    void CheckForDeletedPrefetchFiles();
};

#endif // PREFETCHANALYZER_H