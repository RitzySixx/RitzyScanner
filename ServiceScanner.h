// ServiceScanner.h
#pragma once
#include <windows.h>
#include <vector>
#include <string>

struct ServiceInfo {
    std::string serviceName;   // Real service name
    std::string displayName;   // Display name
    std::string status;        // Running / Stopped / Error
};

namespace ServiceScanner {
    std::vector<ServiceInfo> CheckServices();
    void ExportToCSV(const std::vector<ServiceInfo>& services, const std::string& filename);
    void SetConsoleColor(WORD color);
    void ResetConsoleColor();
}