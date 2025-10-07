#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "PcaAppLaunch.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <codecvt>
#include <locale>
#include <algorithm>
#include <cctype>
#include <mscat.h>
#include <SoftPub.h>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;
namespace PcaAppLaunch {

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

    // Export to CSV
    void ExportToCSV(const std::vector<PcaEntry>& entries, const std::string& filename) {
        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to create CSV file: " << filename << std::endl;
            return;
        }

        csv << "Execution Time,Creation Time,Access Time,Write Time,Name,Path,Signature,Trusted,SHA256,File Size\n";

        for (const auto& entry : entries) {
            csv << "\"" << entry.executionTime << "\","
                << "\"" << entry.creationTime << "\","
                << "\"" << entry.accessTime << "\","
                << "\"" << entry.writeTime << "\","
                << "\"" << entry.name << "\","
                << "\"" << entry.path << "\","
                << "\"" << entry.signature << "\","
                << "\"" << entry.trusted << "\","
                << "\"" << entry.sha256 << "\","
                << entry.fileSize << "\n";
        }

        csv.close();
        std::cout << "Exported " << entries.size() << " entries to " << filename << std::endl;
    }

    std::vector<PcaEntry> ParsePcaAppLaunch() {
        std::vector<PcaEntry> entries;
        std::string filePath = "C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt";

        if (!fs::exists(filePath)) {
            std::cout << "PcaAppLaunchDic.txt not found, skipping.\n";
            return entries;
        }

        std::ifstream file(filePath);
        if (!file) {
            std::cerr << "Failed to open PcaAppLaunchDic.txt\n";
            return entries;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Trim whitespace
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), line.end());

            if (line.empty()) continue;

            // Split by '|'
            size_t pos = line.find('|');
            if (pos == std::string::npos) continue;

            std::string pathStr = line.substr(0, pos);
            std::string executionTime = line.substr(pos + 1);

            // Trim
            pathStr.erase(pathStr.begin(), std::find_if(pathStr.begin(), pathStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            pathStr.erase(std::find_if(pathStr.rbegin(), pathStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), pathStr.end());
            executionTime.erase(executionTime.begin(), std::find_if(executionTime.begin(), executionTime.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            executionTime.erase(std::find_if(executionTime.rbegin(), executionTime.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), executionTime.end());

            std::string path = pathStr;
            std::string signature;
            std::string trusted;
            std::string sha256;
            std::string fileSizeStr;
            std::string creationTimeStr;
            std::string accessTimeStr;
            std::string writeTimeStr;
            std::string name;

            try {
                std::wstring wpath(path.begin(), path.end());
                signature = CheckFileSignature(wpath);

                if (signature == "Deleted") {
                    trusted = "Deleted";
                    sha256 = "";
                    fileSizeStr = "";
                    creationTimeStr = "";
                    accessTimeStr = "";
                    writeTimeStr = "";
                    name = "";
                }
                else {
                    if (signature == "Invalid") {
                        trusted = "Untrusted"; // no digital signature
                    }
                    else {
                        trusted = IsSignatureTrusted(signature, wpath); // signed file, check trust
                    }

                    std::wstring sha256W = ComputeSHA256(wpath);
                    sha256 = WideToUTF8(sha256W);
                    fileSizeStr = std::to_string(fs::file_size(wpath));

                    FILETIME ftCreate = {}, ftAccess = {}, ftWrite = {};
                    GetFileTimes(wpath, ftCreate, ftAccess, ftWrite);
                    creationTimeStr = WideToUTF8(GetSystemTimeString(ftCreate));
                    accessTimeStr = WideToUTF8(GetSystemTimeString(ftAccess));
                    writeTimeStr = WideToUTF8(GetSystemTimeString(ftWrite));

                    std::wstring nameW = fs::path(wpath).filename().wstring();
                    name = WideToUTF8(nameW);
                }
            }
            catch (const std::exception&) {
                signature = "Deleted";
                trusted = "Deleted";
                sha256 = "";
                fileSizeStr = "";
                creationTimeStr = "";
                accessTimeStr = "";
                writeTimeStr = "";
                name = "";
            }

            entries.push_back({
                executionTime,
                path,
                signature,
                trusted,
                sha256,
                fileSizeStr,
                creationTimeStr,
                accessTimeStr,
                writeTimeStr,
                name
            });
        }

        ExportToCSV(entries, "PcaAppLaunch.csv");
        return entries;
    }
}