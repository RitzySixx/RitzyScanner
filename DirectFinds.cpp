#include "DirectFinds.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <vector>
#include <string>

namespace fs = std::filesystem;

std::vector<Finding> DirectFinds::ScanDirectFinds() {
    std::vector<Finding> findings;

    // Get user profile path for dynamic paths
    PWSTR pPath = NULL;
    std::string userProfile, localAppData;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &pPath))) {
        std::wstring ws(pPath);
        userProfile = std::string(ws.begin(), ws.end());
        CoTaskMemFree(pPath);
    }
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pPath))) {
        std::wstring ws(pPath);
        localAppData = std::string(ws.begin(), ws.end());
        CoTaskMemFree(pPath);
    }
    if (userProfile.empty() || localAppData.empty()) {
        return findings; // Cannot proceed without paths
    }

    // Check for d3d10.dll
    std::string fiveMPlugins = localAppData + "\\FiveM\\FiveM.app\\plugins\\";
    std::string d3d10Path = fiveMPlugins + "d3d10.dll";
    if (fs::exists(d3d10Path)) {
        findings.push_back({ "d3d10.dll Found", d3d10Path, "" });
    }

    // Check for .meta files in ai folder
    std::string aiPath = localAppData + "\\FiveM\\FiveM.app\\citizen\\common\\data\\ai\\";
    if (fs::exists(aiPath)) {
        try {
            for (const auto& entry : fs::directory_iterator(aiPath, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file() && entry.path().extension() == ".meta") {
                    findings.push_back({ ".meta File in ai", entry.path().string(), "" });
                }
            }
        }
        catch (const std::exception&) {}
    }

    // Check x64a.rpf size in GTA V dirs
    std::vector<std::string> gtaDirs = {
        "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Grand Theft Auto V",
        "C:\\Program Files\\Epic Games\\GrandTheftAutoV",
        "C:\\Program Files\\Epic Games\\GTAV",
        "C:\\Program Files\\Rockstar Games\\Grand Theft Auto V"
    };
    // Add WindowsApps GTA V folders
    std::string windowsApps = "C:\\Program Files\\WindowsApps";
    if (fs::exists(windowsApps)) {
        try {
            for (const auto& entry : fs::directory_iterator(windowsApps, fs::directory_options::skip_permission_denied)) {
                if (entry.is_directory() && entry.path().filename().string().rfind("RockstarGames.GrandTheftAutoV_", 0) == 0) {
                    gtaDirs.push_back(entry.path().string());
                }
            }
        }
        catch (const std::exception&) {}
    }
    for (const auto& dir : gtaDirs) {
        if (fs::exists(dir)) {
            std::string rpf = dir + "\\x64a.rpf";
            if (fs::exists(rpf)) {
                try {
                    uintmax_t sizeKB = fs::file_size(rpf) / 1024;
                    if (sizeKB != 47566) {
                        findings.push_back({ "x64a.rpf Size Mismatch", rpf, "Size: " + std::to_string(sizeKB) + " KB" });
                    }
                }
                catch (const std::exception&) {}
            }
        }
    }

    // Export to CSV
    std::ofstream csv("DirectFinds.csv");
    if (csv.is_open()) {
        csv << "Type,Path,Details\n";
        for (const auto& f : findings) {
            csv << "\"" << f.type << "\",\"" << f.path << "\",\"" << f.details << "\"\n";
        }
        csv.close();
    }

    return findings;
}