#include "ServiceScanner.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>

std::vector<std::wstring> targetServices = {
    L"PcaSvc", L"CDPSvc", L"DPS", L"SSDPSRV", L"UmRdpService", L"DiagTrack",
    L"SysMain", L"EventLog", L"CDPUserSvc_7fc96", L"Dnscache", L"Appinfo",
    L"vmicvss", L"VSS", L"VSSrv", L"VSStandardCollector"
};

namespace ServiceScanner {

    void SetConsoleColor(WORD color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    void ResetConsoleColor() {
        SetConsoleColor(7); // default gray
    }

    std::vector<ServiceInfo> CheckServices() {
        std::vector<ServiceInfo> results;

        SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            std::cerr << "Cannot connect to Service Control Manager. Access Denied.\n";
            return results;
        }

        for (const auto& svcName : targetServices) {

            DWORD displayNameLen = 256;
            wchar_t displayName[256];
            if (!GetServiceDisplayName(hSCManager, svcName.c_str(), displayName, &displayNameLen)) {
                wcscpy_s(displayName, L"N/A");
            }

            // Blue for "Checking ___ service"
            SetConsoleColor(9);
            std::wcout << L"Checking " << displayName << L" (" << svcName << L") ... ";
            ResetConsoleColor();

            SERVICE_STATUS_PROCESS ssStatus;
            DWORD dwBytesNeeded = 0;

            SC_HANDLE hService = OpenService(hSCManager, svcName.c_str(), SERVICE_QUERY_STATUS);
            ServiceInfo info;
            info.serviceName = std::string(svcName.begin(), svcName.end());
            info.displayName = std::string(displayName, displayName + wcslen(displayName));

            if (!hService) {
                // Red for Not Found / Access Denied
                SetConsoleColor(12);
                std::wcout << L"Not Found / Access Denied\n";
                ResetConsoleColor();
                info.status = "Not Found / Access Denied";
                results.push_back(info);
                continue;
            }

            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssStatus, sizeof(ssStatus), &dwBytesNeeded)) {

                if (ssStatus.dwCurrentState == SERVICE_RUNNING) {
                    // Green for Running
                    SetConsoleColor(10);
                    std::wcout << L"Running\n";
                    ResetConsoleColor();
                    info.status = "Running";
                }
                else {
                    // Red for Stopped
                    SetConsoleColor(12);
                    std::wcout << L"Stopped\n";
                    ResetConsoleColor();
                    info.status = "Stopped";
                }
            }
            else {
                // Red for Query Failed
                SetConsoleColor(12);
                std::wcout << L"Query Failed\n";
                ResetConsoleColor();
                info.status = "Query Failed";
            }

            CloseServiceHandle(hService);
            results.push_back(info);
        }

        CloseServiceHandle(hSCManager);

        ExportToCSV(results, "Services.csv");
        return results;
    }

    void ExportToCSV(const std::vector<ServiceInfo>& services, const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return;

        size_t maxServiceLen = 12;
        size_t maxDisplayLen = 12;
        size_t maxStatusLen = 6;
        for (const auto& svc : services) {
            if (svc.serviceName.length() > maxServiceLen) maxServiceLen = svc.serviceName.length();
            if (svc.displayName.length() > maxDisplayLen) maxDisplayLen = svc.displayName.length();
            if (svc.status.length() > maxStatusLen) maxStatusLen = svc.status.length();
        }

        // Header
        file << std::left << std::setw(maxServiceLen) << "ServiceName" << ","
            << std::setw(maxDisplayLen) << "DisplayName" << ","
            << std::setw(maxStatusLen) << "Status" << "\n";

        // Data
        for (const auto& svc : services) {
            file << std::left << std::setw(maxServiceLen) << svc.serviceName << ","
                << std::setw(maxDisplayLen) << svc.displayName << ","
                << std::setw(maxStatusLen) << svc.status << "\n";
        }

        file.close();
    }

}
