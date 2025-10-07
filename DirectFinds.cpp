#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "DirectFinds.h"
#include "strings.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <set>
#include <wincrypt.h>
#include <wintrust.h>
#include <codecvt>
#include <locale>
#include <algorithm>
#include <cctype>
#include <array>
#include <mscat.h>
#include <SoftPub.h>
#include <iostream>
#include <iomanip>
#include <regex>
#include <objbase.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")

namespace fs = std::filesystem;
namespace DirectFinds {
    std::mutex findingsMutex;
    std::mutex packedFindingsMutex;
    std::mutex processedFilesMutex;
    std::set<std::wstring> processedFiles; // Track files by SHA256
    std::set<std::wstring> processedPaths; // Track unique CSV paths
    std::set<std::wstring> scannedDirs; // Track scanned directories for deleted files

    // Utility to convert wstring to string
    std::string WideToUTF8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    // Get file times
    bool GetFileTimes(const std::wstring& filePath, FILETIME& ftCreate, FILETIME& ftAccess, FILETIME& ftWrite) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        bool success = GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite);
        CloseHandle(hFile);
        return success;
    }

    // Format FILETIME to string
    std::wstring GetSystemTimeString(const FILETIME& ft) {
        if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) return L"N/A";
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        wchar_t buffer[128];
        swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }

    // Compute SHA256 hash
    std::wstring ComputeSHA256(const std::wstring& filePath) {
        std::wstring ext = fs::path(filePath).extension().wstring();
        if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
            return L"Skipped (Media File)";
        }

        std::wstring hashStr = L"";
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return hashStr;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return hashStr;
        }

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return hashStr;
        }

        BYTE buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                CloseHandle(hFile);
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return hashStr;
            }
        }

        CloseHandle(hFile);

        DWORD hashSize = 32;
        BYTE hashBytes[32];
        if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashSize, 0)) {
            std::wstringstream ss;
            for (DWORD i = 0; i < hashSize; ++i) {
                ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)hashBytes[i];
            }
            hashStr = ss.str();
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hashStr;
    }

    // Check file signature
    std::string CheckFileSignature(const std::wstring& filePath) {
        std::wstring ext = fs::path(filePath).extension().wstring();
        if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
            return "Invalid"; // Media files flagged as Invalid
        }

        std::string filePathA = WideToUTF8(filePath);
        WINTRUST_FILE_INFO fileData;
        memset(&fileData, 0, sizeof(fileData));
        fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileData.pcwszFilePath = filePath.c_str();
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
            HANDLE hFile = CreateFileA(filePathA.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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

    // Check if signature is trusted
    std::string IsSignatureTrusted(std::string& signatureStatus, const std::wstring& filePath) {
        if (signatureStatus == "Invalid" && (_wcsicmp(fs::path(filePath).extension().wstring().c_str(), L".png") == 0 ||
            _wcsicmp(fs::path(filePath).extension().wstring().c_str(), L".mp3") == 0 ||
            _wcsicmp(fs::path(filePath).extension().wstring().c_str(), L".mp4") == 0)) {
            return "Untrusted"; // Media files flagged as Untrusted
        }

        std::string filePathA = WideToUTF8(filePath);
        LONG lStatus;
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = 0;
        winTrustData.pFile = &fileInfo;

        lStatus = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        if (lStatus == ERROR_SUCCESS) {
            return "Trusted";
        }
        else if (lStatus == TRUST_E_NOSIGNATURE) {
            HCATADMIN hCatAdmin;
            if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
                HANDLE hFile = CreateFileA(filePathA.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD dwHashSize;
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0)) {
                        BYTE* pbHash = new BYTE[dwHashSize];
                        if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0)) {
                            HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
                            if (hCatInfo) {
                                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                                delete[] pbHash;
                                CloseHandle(hFile);
                                CryptCATAdminReleaseContext(hCatAdmin, 0);
                                signatureStatus = "Valid (Catalog)";
                                return "Trusted";
                            }
                        }
                        delete[] pbHash;
                    }
                    CloseHandle(hFile);
                }
                CryptCATAdminReleaseContext(hCatAdmin, 0);
            }

            signatureStatus = "Unsigned";
            return "Unsigned";
        }
        else {
            signatureStatus = "Invalid";
            return "Untrusted";
        }
    }

    // Calculate file entropy
    double CalculateEntropy(const std::string& data) {
        if (data.empty()) return 0.0;
        std::array<int, 256> freq = { 0 };
        for (char c : data) {
            freq[static_cast<unsigned char>(c)]++;
        }
        double ent = 0.0;
        double len = data.size();
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                ent -= p * std::log2(p);
            }
        }
        return ent;
    }

    // Read file content for YARA scanning
    std::pair<std::string, std::wstring> ReadFileContent(const std::wstring& filePath) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return { "", L"" };
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 100 * 1024 * 1024) {
            CloseHandle(hFile);
            return { "", L"" };
        }

        std::vector<char> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hFile);
            return { "", L"" };
        }
        CloseHandle(hFile);

        std::string asciiContent(buffer.begin(), buffer.begin() + bytesRead);
        std::wstring wideContent;
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, asciiContent.c_str(), -1, NULL, 0);
        if (wideSize > 0) {
            wideContent.resize(wideSize);
            MultiByteToWideChar(CP_UTF8, 0, asciiContent.c_str(), -1, &wideContent[0], wideSize);
        }

        return { asciiContent, wideContent };
    }

    // YARA rules for generic cheats and other detections
    const std::vector<YaraRule> cheatRules = {
        {
            "Generic Cheat (A)",
            {},
            {},
            {
                "!This program cannot be run in DOS mode.",
                "dagger", "bottle", "crowbar", "unarmed", "flashlight", "golfclub", "hammer",
                "hatchet", "knuckle", "knine", "machete", "switchblade", "nightstick", "wrench",
                "battleaxe", "poolcue", "stone_hatchet", "pistol", "pistol_mk2", "combatpistol",
                "appistol", "stungun", "pistol50", "snspistol", "snspistol_mk2", "heavypistol",
                "vintagepistol", "flaregun", "marksmanpistol", "revolver", "revolver_mk2",
                "doubleaction", "raypistol", "ceramicpistol", "navyrevolver", "microsmg",
                "smg_mk2", "assaultsmg", "combatpdw", "machinepistol", "minismg", "raycarbine",
                "pumpshotgun", "pumpshotgun_mk2", "sawnoffshotgun", "assaultshotgun",
                "bullpupshotgun", "musket", "heavyshotgun", "dbshotgun", "autoshotgun",
                "assaultrifle", "assaultrifle_mk2", "carbinerifle", "carbinerifle_mk2",
                "advancedrifle", "specialcarbine", "specialcarbine_mk2", "bullpuprifle",
                "bullpuprifle_mk2", "compactrifle", "combatmg", "combatmg_mk2", "gusenberg",
                "sniperrifle", "heavysniper", "heavysniper_mk2", "marksmanrifle",
                "marksmanrifle_mk2", "grenadelauncher", "grenadelauncher_smoke", "minigun",
                "firework", "railgun", "hominglauncher", "compactlauncher", "rayminigun",
                "grenade", "bzgas", "smokegrenade", "flare", "molotov", "stickybomb",
                "proxmine", "snowball", "pipebomb", "general_noclip_enabled",
                "general_noclip_speed", "keybinds_menu_open", "keybinds_aimbot",
                "aimbot_enabled", "aimbot_draw_selected_bone", "aimbot_selected_bone",
                "aimbot_selected_bone_color", "aimbot_smooth_enabled", "aimbot_smooth_speed",
                "aimbot_draw_fov", "aimbot_fov_size", "aimbot_fov_color", "vehicles_enabled",
                "vehicles_range", "vehicles_enable_vehicle_count", "players_enabled",
                "players_range", "players_bones_ebabled", "players_bones_color",
                "players_box_enabled", "players_box_type", "players_box_color",
                "players_health_bar_enabled", "players_health_bar_type",
                "players_health_bar_color", "players_armor_bar_enabled",
                "players_armor_bar_type", "players_armor_bar_color", "players_weapon_enabled",
                "players_weapon_color", "players_distance_enabled", "players_distance_color",
                "players_enable_player_count", "players_enable_admin_count"
            },
            {},
            0,
            6,
            6,
            false
        },
        {
            "Generic Cheat (B)",
            {},
            {},
            {
                "!This program cannot be run in DOS mode.",
                "\\config\\config.json",
                "Enabled##Aimbot",
                "Style##PedVisualsBox"
            },
            {},
            0,
            4,
            4,
            true
        },
        {
            "CCleaner",
            {
                "Ccleaner.exe",
                "Ccleaner64.exe",
                "CCleaner.Windows.IPC.NamedPipes",
                "CCleanerDU.dll"
            },
            {},
            {
                "ccleaner.com",
                "dlc.ccleaner.com",
                "https://www.ccleaner.com"
            },
            {},
            0,
            2,
            2,
            false
        },
        {
            "Generic Cheat (C)",
            {},
            {},
            {
                "<requestedExecutionLevel level='asInvoker' uiAccess='false' />",
                "W1,$_@",
                "14$_A:",
                "AR1,$L",
                "AR1,$D",
                "1<$A[A",
                "1,$_fA",
                "W1,$fA",
                "$A[fE;",
                "AR1,$I",
                "14$]Hc",
                "U14$fD",
                "AR1,$A",
                "AR1<$AZ@",
                "1<$AZHc",
                "AS1,$A[@",
                "$A[fD;",
                "1,$fD#",
                "AR1<$fA",
                "AR1,$AZHc"
            },
            {},
            0,
            12,
            12,
            false
        },
        {
            "Generic Cheat (D)",
            {},
            {},
            {
                "h.rsrc",
                "AS1,$A",
                ".AaVXM",
                "AS1<$I",
                "AS1,$A[Hc",
                "1<$A[Hc",
                "Oh4e1z",
                "AS1,$fE",
                "AS1<$A",
                "1,$A[A",
                "1<$fA#",
                "AS1,$A[",
                "1,$_Hc",
                "1,$A[Hc",
                "AS1<$fD",
                "AS1,$fA",
                "14$_Hc"
            },
            {},
            0,
            0,
            10,
            false
        },
        {
            "Generic Cheat (E)",
            {},
            {},
            {
                "V1<$fA",
                "e14$AYHc",
                "V1<$fD",
                "V1<$^H",
                "81<$fA",
                "14$AYHc",
                "$AYfD;",
                "V1<$^Hc",
                "O1<$fE",
                "W1,$_fA",
                "AQ14$A",
                "1<$^Hc",
                "AQ14$AY",
                "AZA[fA",
                "AQ14$D",
                "V1<$^f",
                "$AYfA;",
                "AYA^fD",
                "1<$fE3",
                "1<$^E:"
            },
            {},
            0,
            0,
            10,
            false
        },
        {
            "Generic Cheat (F)",
            {},
            {},
            {
                "1<$[Hc",
                "S1<$fA",
                "AS1<$A[Hc",
                "14$_E:",
                "$A[fA;",
                "W14$_H",
                "1<$]Hc",
                "W14$_Hc",
                "W14$_fD;",
                "S1<$[Hc",
                "S1<$Hc",
                "U1<$fA",
                "W1,$_A",
                "AS1<$fD",
                "1<$fE+"
            },
            {},
            0,
            0,
            10,
            false
        },
        {
            "Suspicious PS",
            {
                "-NoProfile -NonInteractive -EncodedCommand",
                "-NoProfile -NonInteractive -Command",
                "-ExecutionPolicy Bypass",
                "pwsh -NoProfile -NonInteractive -EncodedCommand",
                "-EncodedCommand",
                "iex",
                "iwr",
                "irm",
                "Get-Content | IEX",
                "IEX (Get-Content",
                "Invoke-WebRequest",
                "DownloadString",
                "DownloadFile",
                "WebClient().DownloadFile",
                "WebClient.DownloadFile"
            },
            {},
            {
                "Invoke-Expression",
                "IEX(",
                "DownloadString",
                "FromBase64String",
                "Invoke-WebRequest",
                "Invoke-RestMethod",
                "New-Object Net.WebClient",
                "Invoke-Command",
                "System.Reflection.Assembly::Load",
                "Start-Process",
                "Add-Type",
                "DownloadFile",
                "ConvertTo-SecureString",
                "Base64String",
                "http://",
                "https://",
                "raw.githubusercontent.com",
                "gist.githubusercontent.com",
                "githubusercontent",
                "pastebin.com",
                "bit.ly",
                "tinyurl.com",
                ".php",
                ".exe",
                ".zip",
                ".dll",
                "/raw/",
                "/download/"
            },
            {},
            0,
            2,
            4,
            false
        },
        {
            "Possible_InMemory_Modifications",
            {
                "ReflectiveLoader",
                "ReflectiveDLLMain",
                "ManualMap",
                "ReflectiveLoad",
                "ReflectiveInit"
            },
            {},
            {
                "VirtualAlloc",
                "VirtualProtect",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "NtWriteVirtualMemory",
                "CreateRemoteThread",
                "CreateThread",
                "LoadLibraryA",
                "LoadLibraryW",
                "GetProcAddress",
                "RtlMoveMemory",
                "RtlCopyMemory",
                "NtMapViewOfSection",
                "ZwUnmapViewOfSection",
                "MapViewOfFile",
                "QueueUserAPC",
                "ResumeThread"
            },
            {},
            0,
            1,
            4,
            false
        }
    };

    // Check if file is excluded (system-protected or Microsoft-signed)
    bool IsExcluded(const std::wstring& path) {
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), towlower);
        wchar_t winDir[MAX_PATH];
        wchar_t progFiles[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        GetEnvironmentVariableW(L"ProgramFiles", progFiles, MAX_PATH);
        std::wstring windowsDir = winDir;
        std::wstring programFiles = progFiles;
        std::transform(windowsDir.begin(), windowsDir.end(), windowsDir.begin(), towlower);
        std::transform(programFiles.begin(), programFiles.end(), programFiles.begin(), towlower);

        std::vector<std::wstring> excludedPrefixes = {
            windowsDir + L"\\",
            programFiles + L"\\windows defender\\",
            programFiles + L"\\windowsapps\\",
            L"c:\\system volume information\\",
            L"c:\\recovery\\",
            L"c:\\$winre\\"
        };

        for (const auto& prefix : excludedPrefixes) {
            if (lowerPath.find(prefix) == 0) {
                return true;
            }
        }

        std::string signature = CheckFileSignature(path);
        std::string trusted = IsSignatureTrusted(signature, path);
        if (signature.find("Valid") != std::string::npos && trusted == "Trusted") {
            std::wstring filename = fs::path(path).filename().wstring();
            if (filename.find(L"microsoft") != std::wstring::npos || filename.find(L"windows") != std::wstring::npos) {
                return true;
            }
        }

        return false;
    }

    // Struct to hold CSV file info
    struct CSVFileInfo {
        std::wstring path;
        std::string signature;
        std::string trusted;
        std::wstring csvName;
    };

    // Extract paths, signatures, trust status, and CSV name
    std::vector<CSVFileInfo> GetPathsFromCSV(const std::wstring& csvPath) {
        std::vector<CSVFileInfo> fileInfos;
        std::ifstream csv(WideToUTF8(csvPath));
        if (!csv) return fileInfos;

        std::string line;
        bool headerParsed = false;
        int pathCol = -1, sigCol = -1, trustCol = -1;
        std::wstring csvName = fs::path(csvPath).filename().wstring();

        // Parse header
        if (std::getline(csv, line)) {
            std::stringstream ss(line);
            std::string token;
            int col = 0;
            while (std::getline(ss, token, ',')) {
                if (!token.empty() && token.front() == '"') token.erase(0, 1);
                if (!token.empty() && token.back() == '"') token.pop_back();
                if (token == "Path") pathCol = col;
                if (token == "Signature") sigCol = col;
                if (token == "Trusted") trustCol = col;
                col++;
            }
            headerParsed = (pathCol != -1 && sigCol != -1 && trustCol != -1);
        }

        if (!headerParsed) return fileInfos;

        // Parse rows
        while (std::getline(csv, line)) {
            std::stringstream ss(line);
            std::vector<std::string> tokens;
            std::string token;
            while (std::getline(ss, token, ',')) {
                if (!token.empty() && token.front() == '"') token.erase(0, 1);
                if (!token.empty() && token.back() == '"') token.pop_back();
                tokens.push_back(token);
            }

            if (tokens.size() <= static_cast<size_t>(pathCol) ||
                tokens.size() <= static_cast<size_t>(sigCol) ||
                tokens.size() <= static_cast<size_t>(trustCol)) {
                continue;
            }

            std::wstring wtoken = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(tokens[pathCol]);
            if (wtoken.size() > 3 && iswalpha(wtoken[0]) && wtoken[1] == L':' && wtoken[2] == L'\\') {
                std::string signature = tokens[sigCol];
                std::string trusted = tokens[trustCol];
                // Include all files (even "Deleted") for directory scanning if deleted
                if (signature != "Valid (Authenticode)" && signature != "Valid (Catalog)") {
                    fileInfos.push_back({ wtoken, signature, trusted, csvName });
                }
            }
        }
        return fileInfos;
    }

    // Scan directory recursively
    void ScanDirectory(const std::wstring& dirPath, const std::wstring& deletedFilePath, std::vector<CSVFileInfo>& fileInfos) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::wstring filePath = entry.path().wstring();
                    if (filePath == deletedFilePath) continue; // Skip the deleted file
                    if (IsExcluded(filePath)) continue;

                    std::wstring ext = fs::path(filePath).extension().wstring();
                    if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
                        fileInfos.push_back({ filePath, "Invalid", "Untrusted", L"Directory Scan" });
                        continue;
                    }

                    std::string signature = CheckFileSignature(filePath);
                    std::string trusted = IsSignatureTrusted(signature, filePath);
                    if (signature != "Valid (Authenticode)" && signature != "Valid (Catalog)") {
                        fileInfos.push_back({ filePath, signature, trusted, L"Directory Scan" });
                    }
                }
            }
        }
        catch (const std::exception&) {}
    }

    // Scan limited directories for deleted files: grandparent non-recursive, parent non-recursive, immediate subdirs non-recursive
    void ScanLimitedDirectory(const std::wstring& parentDir, std::vector<CSVFileInfo>& fileInfos) {
        auto scanNonRecursive = [&](const std::wstring& dir) {
            if (!fs::exists(dir) || !fs::is_directory(dir)) return;
            try {
                for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_regular_file()) {
                        std::wstring filePath = entry.path().wstring();
                        if (IsExcluded(filePath)) continue;

                        std::wstring ext = fs::path(filePath).extension().wstring();
                        if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
                            fileInfos.push_back({ filePath, "Invalid", "Untrusted", L"Directory Scan" });
                            continue;
                        }

                        std::string signature = CheckFileSignature(filePath);
                        std::string trusted = IsSignatureTrusted(signature, filePath);
                        if (signature != "Valid (Authenticode)" && signature != "Valid (Catalog)") {
                            fileInfos.push_back({ filePath, signature, trusted, L"Directory Scan" });
                        }
                    }
                }
            }
            catch (const std::exception&) {}
        };

        // Scan grandparent non-recursive (one folder up, only 1 level)
        fs::path p(parentDir);
        if (p.has_parent_path()) {
            fs::path grandparent = p.parent_path();
            scanNonRecursive(grandparent.wstring());
        }

        // Scan parent non-recursive (exact path)
        scanNonRecursive(parentDir);

        // Scan immediate subdirs non-recursive (one folder down)
        if (fs::exists(parentDir) && fs::is_directory(parentDir)) {
            try {
                for (const auto& entry : fs::directory_iterator(parentDir, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_directory()) {
                        scanNonRecursive(entry.path().wstring());
                    }
                }
            }
            catch (const std::exception&) {}
        }
    }

    // Scan files with YARA rules and packed file checks
    void ScanFileWithYara(const std::vector<CSVFileInfo>& fileBatch, std::vector<Finding>& findings, std::vector<Finding>& packedFindings) {
        for (const auto& fileInfo : fileBatch) {
            const std::wstring& filePath = fileInfo.path;
            std::wstring ext = fs::path(filePath).extension().wstring();
            if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
                continue;
            }

            std::wstring sha256 = ComputeSHA256(filePath);
            {
                std::lock_guard<std::mutex> lock(processedFilesMutex);
                if (processedFiles.find(sha256) != processedFiles.end()) {
                    continue;
                }
                processedFiles.insert(sha256);
            }

            auto [asciiContent, wideContent] = ReadFileContent(filePath);
            if (asciiContent.empty() && wideContent.empty()) {
                continue;
            }

            bool hasYaraMatch = false;
            FILETIME ftCreate = {}, ftAccess = {}, ftWrite = {};
            GetFileTimes(filePath, ftCreate, ftAccess, ftWrite);
            std::string signature = fileInfo.signature;
            std::string trusted = fileInfo.trusted;
            uintmax_t fileSize = fs::exists(filePath) ? fs::file_size(filePath) : 0;
            std::wstring filename = fs::path(filePath).filename().wstring();
            std::wstring csvName = fileInfo.csvName;

            for (const auto& rule : cheatRules) {
                if (hasYaraMatch) break;
                if (rule.maxFileSize > 0 && asciiContent.size() > rule.maxFileSize) continue;

                int xMatchCount = 0;
                int totalMatchCount = 0;

                for (const auto& str : rule.x_strings_ascii) {
                    if (std::search(asciiContent.begin(), asciiContent.end(), str.begin(), str.end()) != asciiContent.end()) {
                        ++xMatchCount;
                        ++totalMatchCount;
                    }
                }
                for (const auto& str : rule.x_strings_wide) {
                    if (std::search(wideContent.begin(), wideContent.end(), str.begin(), str.end()) != wideContent.end()) {
                        ++xMatchCount;
                        ++totalMatchCount;
                    }
                }
                for (const auto& str : rule.s_strings_ascii) {
                    if (std::search(asciiContent.begin(), asciiContent.end(), str.begin(), str.end()) != asciiContent.end()) {
                        ++totalMatchCount;
                    }
                }
                for (const auto& str : rule.s_strings_wide) {
                    if (std::search(wideContent.begin(), wideContent.end(), str.begin(), str.end()) != wideContent.end()) {
                        ++totalMatchCount;
                    }
                }

                int totalXStrings = rule.x_strings_ascii.size() + rule.x_strings_wide.size();
                int totalAllStrings = totalXStrings + rule.s_strings_ascii.size() + rule.s_strings_wide.size();
                bool stringMatch;
                if (rule.allStrings) {
                    stringMatch = (xMatchCount >= totalXStrings) && (totalMatchCount >= totalAllStrings);
                } else {
                    bool xCondition = (totalXStrings == 0) || (xMatchCount >= rule.minXMatches);
                    bool totalCondition = totalMatchCount >= rule.minTotalMatches;
                    stringMatch = xCondition && totalCondition;
                }

                if (stringMatch) {
                    hasYaraMatch = true;
                    Finding finding = {
                        "YARA Match",
                        WideToUTF8(filePath),
                        rule.name,
                        fileSize,
                        WideToUTF8(sha256),
                        signature,
                        trusted,
                        WideToUTF8(GetSystemTimeString(ftCreate)),
                        WideToUTF8(GetSystemTimeString(ftAccess)),
                        WideToUTF8(GetSystemTimeString(ftWrite)),
                        WideToUTF8(filename),
                        WideToUTF8(csvName)
                    };
                    std::lock_guard<std::mutex> lock(findingsMutex);
                    findings.push_back(std::move(finding));
                }
            }

            bool isExecutable = (_wcsicmp(ext.c_str(), L".exe") == 0 || _wcsicmp(ext.c_str(), L".dll") == 0);
            if (isExecutable) {
                double entropy = CalculateEntropy(asciiContent);
                if (entropy >= 7.2) {
                    Finding finding = {
                        "Packed File",
                        WideToUTF8(filePath),
                        "Packed File (Entropy: " + std::to_string(entropy) + ")",
                        fileSize,
                        WideToUTF8(sha256),
                        signature,
                        trusted,
                        WideToUTF8(GetSystemTimeString(ftCreate)),
                        WideToUTF8(GetSystemTimeString(ftAccess)),
                        WideToUTF8(GetSystemTimeString(ftWrite)),
                        WideToUTF8(filename),
                        WideToUTF8(csvName)
                    };
                    std::lock_guard<std::mutex> lock(packedFindingsMutex);
                    packedFindings.push_back(std::move(finding));
                }
            }
        }
    }

    // Export findings to CSV with Location Found
    void ExportToCSV(const std::vector<Finding>& findings, const std::wstring& outputPath, bool includeDetails) {
        std::ofstream csv(WideToUTF8(outputPath));
        if (!csv.is_open()) {
            std::wcerr << L"Failed to create output file: " << outputPath << std::endl;
            return;
        }

        csv << "Creation Time,Access Time,Write Time,Name,Path,Signature,Trusted,SHA256,File Size (Bytes),Details,Location Found\n";

        for (const auto& f : findings) {
            csv << "\"" << f.creationTime << "\","
                << "\"" << f.accessTime << "\","
                << "\"" << f.writeTime << "\","
                << "\"" << f.name << "\","
                << "\"" << f.path << "\","
                << "\"" << f.signature << "\","
                << "\"" << f.trusted << "\","
                << "\"" << f.sha256 << "\","
                << f.fileSize
                << ",\"" << f.details << "\","
                << "\"" << f.locationFound << "\"\n";
        }

        csv.close();
        std::wcout << L"Exported " << findings.size() << L" entries to " << outputPath << std::endl;
    }

    std::vector<Finding> ScanDirectFinds() {
        std::vector<Finding> findings;
        std::vector<Finding> packedFindings;
        processedFiles.clear();
        processedPaths.clear();

        PWSTR pPath = NULL;
        std::wstring userProfile, localAppData;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &pPath))) {
            userProfile = pPath;
            CoTaskMemFree(pPath);
        }
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pPath))) {
            localAppData = pPath;
            CoTaskMemFree(pPath);
        }
        if (userProfile.empty() || localAppData.empty()) {
            return findings;
        }

        std::vector<std::wstring> gtaDirs = {
            L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Grand Theft Auto V",
            L"C:\\Program Files\\Epic Games\\GrandTheftAutoV",
            L"C:\\Program Files\\Epic Games\\GTAV",
            L"C:\\Program Files\\Rockstar Games\\Grand Theft Auto V"
        };

        std::wstring windowsApps = L"C:\\Program Files\\WindowsApps";
        if (fs::exists(windowsApps)) {
            try {
                for (const auto& entry : fs::directory_iterator(windowsApps, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_directory() && entry.path().filename().wstring().rfind(L"RockstarGames.GrandTheftAutoV_", 0) == 0) {
                        gtaDirs.push_back(entry.path().wstring());
                    }
                }
            }
            catch (const std::exception&) {}
        }

        // Check d3d10.dll
        std::wstring fiveMPlugins = localAppData + L"\\FiveM\\FiveM.app\\plugins\\";
        std::wstring d3d10Path = fiveMPlugins + L"d3d10.dll";
        if (fs::exists(d3d10Path)) {
            std::wstring sha256 = ComputeSHA256(d3d10Path);
            {
                std::lock_guard<std::mutex> lock(processedFilesMutex);
                if (processedFiles.find(sha256) == processedFiles.end()) {
                    processedFiles.insert(sha256);
                    std::string signature = CheckFileSignature(d3d10Path);
                    std::string trusted = IsSignatureTrusted(signature, d3d10Path);
                    uintmax_t fileSize = fs::file_size(d3d10Path);
                    FILETIME ftCreate, ftAccess, ftWrite;
                    GetFileTimes(d3d10Path, ftCreate, ftAccess, ftWrite);
                    findings.push_back(Finding{
                        "d3d10.dll Found",
                        WideToUTF8(d3d10Path),
                        "Signature: " + signature + ", Trusted: " + trusted,
                        fileSize,
                        WideToUTF8(sha256),
                        signature,
                        trusted,
                        WideToUTF8(GetSystemTimeString(ftCreate)),
                        WideToUTF8(GetSystemTimeString(ftAccess)),
                        WideToUTF8(GetSystemTimeString(ftWrite)),
                        WideToUTF8(fs::path(d3d10Path).filename().wstring()),
                        "Direct Scan"
                        });
                }
            }
        }

        // Check .meta files in ai folder
        std::wstring aiPath = localAppData + L"\\FiveM\\FiveM.app\\citizen\\common\\data\\ai\\";
        if (fs::exists(aiPath)) {
            try {
                for (const auto& entry : fs::directory_iterator(aiPath, fs::directory_options::skip_permission_denied)) {
                    if (entry.is_regular_file() && entry.path().extension() == L".meta") {
                        std::wstring filePath = entry.path().wstring();
                        std::wstring sha256 = ComputeSHA256(filePath);
                        {
                            std::lock_guard<std::mutex> lock(processedFilesMutex);
                            if (processedFiles.find(sha256) == processedFiles.end()) {
                                processedFiles.insert(sha256);
                                std::string signature = CheckFileSignature(filePath);
                                std::string trusted = IsSignatureTrusted(signature, filePath);
                                uintmax_t fileSize = fs::file_size(filePath);
                                FILETIME ftCreate, ftAccess, ftWrite;
                                GetFileTimes(filePath, ftCreate, ftAccess, ftWrite);
                                findings.push_back(Finding{
                                    ".meta File in ai",
                                    WideToUTF8(filePath),
                                    "Signature: " + signature + ", Trusted: " + trusted,
                                    fileSize,
                                    WideToUTF8(sha256),
                                    signature,
                                    trusted,
                                    WideToUTF8(GetSystemTimeString(ftCreate)),
                                    WideToUTF8(GetSystemTimeString(ftAccess)),
                                    WideToUTF8(GetSystemTimeString(ftWrite)),
                                    WideToUTF8(fs::path(filePath).filename().wstring()),
                                    "Direct Scan"
                                    });
                            }
                        }
                    }
                }
            }
            catch (const std::exception&) {}
        }

        // Check x64a.rpf size
        for (const auto& dir : gtaDirs) {
            if (fs::exists(dir)) {
                std::wstring rpf = dir + L"\\x64a.rpf";
                if (fs::exists(rpf)) {
                    try {
                        std::wstring sha256 = ComputeSHA256(rpf);
                        {
                            std::lock_guard<std::mutex> lock(processedFilesMutex);
                            if (processedFiles.find(sha256) == processedFiles.end()) {
                                processedFiles.insert(sha256);
                                uintmax_t sizeKB = fs::file_size(rpf) / 1024;
                                if (sizeKB != 47566) {
                                    std::string signature = CheckFileSignature(rpf);
                                    std::string trusted = IsSignatureTrusted(signature, rpf);
                                    uintmax_t fileSize = fs::file_size(rpf);
                                    FILETIME ftCreate, ftAccess, ftWrite;
                                    GetFileTimes(rpf, ftCreate, ftAccess, ftWrite);
                                    findings.push_back(Finding{
                                        "x64a.rpf Size Mismatch",
                                        WideToUTF8(rpf),
                                        "Size: " + std::to_string(sizeKB) + " KB, Signature: " + signature + ", Trusted: " + trusted,
                                        fileSize,
                                        WideToUTF8(sha256),
                                        signature,
                                        trusted,
                                        WideToUTF8(GetSystemTimeString(ftCreate)),
                                        WideToUTF8(GetSystemTimeString(ftAccess)),
                                        WideToUTF8(GetSystemTimeString(ftWrite)),
                                        WideToUTF8(fs::path(rpf).filename().wstring()),
                                        "Direct Scan"
                                        });
                                }
                            }
                        }
                    }
                    catch (const std::exception&) {}
                }
            }
        }

        // Collect files from CSVs and directories of deleted files
        std::vector<CSVFileInfo> allFiles;
        std::wstring currentDir = fs::current_path().wstring();
        try {
            for (const auto& entry : fs::directory_iterator(currentDir, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::wstring filename = entry.path().filename().wstring();
                    std::wstring lowerFilename = filename;
                    std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::towlower);
                    if (lowerFilename.size() >= 4 && lowerFilename.substr(lowerFilename.size() - 4) == L".csv") {
                        auto fileInfos = GetPathsFromCSV(entry.path().wstring());
                        for (const auto& info : fileInfos) {
                            std::lock_guard<std::mutex> lock(processedFilesMutex);
                            if (processedPaths.find(info.path) == processedPaths.end()) {
                                processedPaths.insert(info.path);
                                if (info.signature == "Deleted") {
                                    std::wstring parentDir = fs::path(info.path).parent_path().wstring();
                                    if (!parentDir.empty() && fs::exists(parentDir) && scannedDirs.find(parentDir) == scannedDirs.end()) {
                                        scannedDirs.insert(parentDir);
                                        ScanLimitedDirectory(parentDir, allFiles);
                                    }
                                }
                                else {
                                    allFiles.push_back(info);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (const std::exception&) {}

        // Process files in batches
        if (!allFiles.empty()) {
            unsigned int threadCount = (std::max)(1U, std::thread::hardware_concurrency());
            std::vector<std::thread> threads;
            size_t batchSize = std::max<size_t>(1, allFiles.size() / threadCount);
            for (size_t i = 0; i < allFiles.size(); i += batchSize) {
                size_t endIndex = std::min<size_t>(i + batchSize, allFiles.size());
                std::vector<CSVFileInfo> batch(allFiles.begin() + i, allFiles.begin() + endIndex);
                threads.emplace_back(ScanFileWithYara, batch, std::ref(findings), std::ref(packedFindings));
            }
            for (auto& t : threads) {
                t.join();
            }
        }

        // Scan for strings in processes and services
        auto stringMatches = ScanProcessesAndServicesForStrings();
        for (const auto& match : stringMatches) {
            findings.push_back(Finding{
                "Memory String Detection",
                "", // path
                match.detectionName + " in " + match.processName,
                0, // fileSize
                "", // sha256
                "", // signature
                "", // trusted
                "", // creationTime
                "", // accessTime
                "", // writeTime
                match.detectionName, // name
                "Memory Scan" // locationFound
            });
        }

        ExportToCSV(findings, L"DirectFinds.csv", true);
        ExportToCSV(packedFindings, L"PackedFiles.csv", false);

        return findings;
    }
}