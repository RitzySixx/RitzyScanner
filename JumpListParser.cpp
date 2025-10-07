#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "JumpListParser.h"
#include <shlobj.h>
#include <propkey.h>
#include <propvarutil.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <codecvt>
#include <locale>
#include <softpub.h>
#include <shlwapi.h>
#include <objbase.h>
#include <shobjidl.h>
#include <atlbase.h>
#include <comutil.h>
#include <oleauto.h>
#include <algorithm>
#include <thread>
#include <mutex>
#include <vector>
#include <set>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace JumpListParser {
    std::mutex entriesMutex;

    std::string WideToUTF8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    std::wstring GetSystemTimeString(const FILETIME& ft) {
        if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) return L"";

        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);

        wchar_t buffer[128];
        swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

        return buffer;
    }

    std::wstring GetFileNameFromPath(const std::wstring& path) {
        size_t lastSlash = path.find_last_of(L"\\/");
        return (lastSlash != std::wstring::npos) ? path.substr(lastSlash + 1) : path;
    }

    std::wstring GetFileExtension(const std::wstring& path) {
        size_t lastDot = path.find_last_of(L".");
        return (lastDot != std::wstring::npos) ? path.substr(lastDot) : L"";
    }

    std::string CheckFileSignature(const std::wstring& filePath) {
        // Skip media files
        std::wstring ext = GetFileExtension(filePath);
        if (_wcsicmp(ext.c_str(), L".png") == 0 || _wcsicmp(ext.c_str(), L".mp3") == 0 || _wcsicmp(ext.c_str(), L".mp4") == 0) {
            return "Skipped (Media File)";
        }

        DWORD attrs = GetFileAttributesW(filePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            return "Deleted";
        }

        WINTRUST_FILE_INFO fileData = {};
        fileData.cbStruct = sizeof(fileData);
        fileData.pcwszFilePath = filePath.c_str();

        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.pFile = &fileData;

        LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        if (lStatus == ERROR_SUCCESS) {
            return "Valid (Authenticode)";
        }

        HCATADMIN hCatAdmin;
        if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwHashSize = 0;
                if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0)) {
                    BYTE* pbHash = new BYTE[dwHashSize];
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0)) {
                        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
                        if (hCatInfo) {
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

    std::string IsSignatureTrusted(const std::string& signatureStatus, const std::wstring& filePath) {
        if (signatureStatus == "Deleted" || signatureStatus == "Skipped (Media File)") {
            return "";
        }

        if (signatureStatus == "Invalid" || signatureStatus == "Unsigned") {
            return "Untrusted";
        }

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.pFile = &fileInfo;

        LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        return (lStatus == ERROR_SUCCESS) ? "Trusted" : "Untrusted";
    }

    std::wstring GetPropertyString(IPropertyStore* pPropStore, const PROPERTYKEY& key) {
        PROPVARIANT propVar;
        PropVariantInit(&propVar);
        if (SUCCEEDED(pPropStore->GetValue(key, &propVar))) {
            wchar_t szValue[1024];
            if (SUCCEEDED(PropVariantToString(propVar, szValue, ARRAYSIZE(szValue)))) {
                PropVariantClear(&propVar);
                return szValue;
            }
            PropVariantClear(&propVar);
        }
        return L"";
    }

    std::wstring ComputeSHA256(const std::wstring& filePath) {
        std::wstring ext = GetFileExtension(filePath);
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

        DWORD hashSize = 32; // SHA256 is 256 bits = 32 bytes
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

    std::vector<JumplistEntry> ParseShellLinkFromStream(const std::vector<BYTE>& streamData, const std::wstring& jumplistFile, const std::wstring& entryType) {
        std::vector<JumplistEntry> entries;

        CComPtr<IPersistStream> pPersistStream;
        CComPtr<IShellLinkW> psl;
        if (FAILED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl))) {
            return entries;
        }

        if (FAILED(psl->QueryInterface(IID_IPersistStream, (void**)&pPersistStream))) {
            return entries;
        }

        CComPtr<IStream> pStream;
        if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &pStream))) {
            return entries;
        }

        ULONG bytesWritten;
        if (FAILED(pStream->Write(streamData.data(), (ULONG)streamData.size(), &bytesWritten))) {
            return entries;
        }

        if (FAILED(pStream->Seek({ 0 }, STREAM_SEEK_SET, NULL))) {
            return entries;
        }

        if (FAILED(pPersistStream->Load(pStream))) {
            return entries;
        }

        CComPtr<IPropertyStore> pPropStore;
        if (FAILED(psl->QueryInterface(IID_IPropertyStore, (void**)&pPropStore))) {
            return entries;
        }

        JumplistEntry entry;
        entry.jumplistFile = jumplistFile;
        entry.entryType = entryType;
        entry.lnkPath = L"In-Memory";

        wchar_t szPath[MAX_PATH] = { 0 };
        wchar_t szArguments[MAX_PATH] = { 0 };
        wchar_t szWorkingDir[MAX_PATH] = { 0 };
        wchar_t szIconPath[MAX_PATH] = { 0 };
        int iIconIndex = 0;

        psl->GetPath(szPath, MAX_PATH, NULL, SLGP_RAWPATH);
        psl->GetArguments(szArguments, MAX_PATH);
        psl->GetWorkingDirectory(szWorkingDir, MAX_PATH);
        psl->GetIconLocation(szIconPath, MAX_PATH, &iIconIndex);

        entry.path = szPath;
        entry.arguments = szArguments;
        entry.workingDir = szWorkingDir;
        entry.iconPath = szIconPath;
        entry.iconIndex = iIconIndex;
        entry.title = GetPropertyString(pPropStore, PKEY_Title);
        entry.appId = GetPropertyString(pPropStore, PKEY_AppUserModel_ID);

        if (!entry.path.empty()) {
            HANDLE hFile = CreateFileW(entry.path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME ftCreate, ftAccess, ftWrite;
                if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                    entry.creationTime = ftCreate;
                    entry.accessTime = ftAccess;
                    entry.writeTime = ftWrite;
                }
                LARGE_INTEGER fileSize;
                if (GetFileSizeEx(hFile, &fileSize)) {
                    entry.fileSize = fileSize.QuadPart;
                }
                CloseHandle(hFile);

                entry.sha256 = ComputeSHA256(entry.path);
            }
            else {
                entry.fileSize = -1;
                entry.sha256 = L"";
            }
        }
        else {
            entry.fileSize = -1;
            entry.sha256 = L"";
        }

        HANDLE hJumplistFile = CreateFileW(jumplistFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hJumplistFile != INVALID_HANDLE_VALUE) {
            FILETIME ftCreate, ftAccess, ftWrite;
            if (GetFileTime(hJumplistFile, &ftCreate, &ftAccess, &ftWrite)) {
                entry.jumplistTimestamp = ftWrite;
            }
            CloseHandle(hJumplistFile);
        }

        if (!entry.path.empty()) {
            std::string sigStatus = CheckFileSignature(entry.path);
            entry.signatureStatus = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sigStatus);
            entry.trusted = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(IsSignatureTrusted(sigStatus, entry.path));
        }
        else {
            entry.signatureStatus = L"N/A";
            entry.trusted = L"";
        }

        entries.push_back(entry);
        return entries;
    }

    void ParseAutomaticDestinationsThread(const std::wstring& filePath, std::vector<JumplistEntry>& allEntries) {
        std::vector<JumplistEntry> entries;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize > 100 * 1024 * 1024) { // Limit to 100MB
            CloseHandle(hFile);
            return;
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hFile);
            return;
        }
        CloseHandle(hFile);

        CComPtr<IStorage> pStorage;
        if (FAILED(StgOpenStorageEx(filePath.c_str(), STGM_READ | STGM_SHARE_DENY_WRITE,
            STGFMT_STORAGE, 0, NULL, NULL, IID_IStorage, (void**)&pStorage))) {
            return;
        }

        CComPtr<IEnumSTATSTG> pEnum;
        if (FAILED(pStorage->EnumElements(0, NULL, 0, &pEnum))) {
            return;
        }

        STATSTG stat;
        while (pEnum->Next(1, &stat, NULL) == S_OK) {
            if (wcscmp(stat.pwcsName, L"DestList") == 0) {
                CoTaskMemFree(stat.pwcsName);
                continue;
            }

            bool isLinkStream = false;
            for (int i = 0; stat.pwcsName[i]; i++) {
                if (iswdigit(stat.pwcsName[i])) {
                    isLinkStream = true;
                    break;
                }
            }

            if (!isLinkStream) {
                CoTaskMemFree(stat.pwcsName);
                continue;
            }

            CComPtr<IStream> pStream;
            if (SUCCEEDED(pStorage->OpenStream(stat.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream))) {
                STATSTG streamStat;
                if (SUCCEEDED(pStream->Stat(&streamStat, STATFLAG_DEFAULT)) && streamStat.cbSize.QuadPart < 10 * 1024 * 1024) { // Limit to 10MB per stream
                    std::vector<BYTE> streamBuffer(streamStat.cbSize.LowPart);
                    ULONG bytesReadStream;
                    if (SUCCEEDED(pStream->Read(streamBuffer.data(), streamStat.cbSize.LowPart, &bytesReadStream))) {
                        auto streamEntries = ParseShellLinkFromStream(streamBuffer, filePath, L"Automatic");
                        std::lock_guard<std::mutex> lock(entriesMutex);
                        allEntries.insert(allEntries.end(), streamEntries.begin(), streamEntries.end());
                    }
                }
            }

            CoTaskMemFree(stat.pwcsName);
        }
    }

    void ParseCustomDestinationsThread(const std::wstring& filePath, std::vector<JumplistEntry>& allEntries) {
        std::vector<JumplistEntry> entries;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize > 100 * 1024 * 1024) { // Limit to 100MB
            CloseHandle(hFile);
            return;
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hFile);
            return;
        }
        CloseHandle(hFile);

        const BYTE pattern[] = { 0x4C, 0x00, 0x00, 0x00 };
        size_t offset = 0;
        while (offset < buffer.size()) {
            auto start_it = std::search(buffer.begin() + offset, buffer.end(), pattern, pattern + sizeof(pattern));
            if (start_it == buffer.end()) break;

            size_t header_pos = start_it - buffer.begin();
            auto end_it = std::search(start_it + sizeof(pattern), buffer.end(), pattern, pattern + sizeof(pattern));
            size_t next_pos = (end_it != buffer.end()) ? end_it - buffer.begin() : buffer.size();

            size_t chunk_size = next_pos - header_pos;
            if (chunk_size > 0 && chunk_size < 10 * 1024 * 1024) { // Limit to 10MB per chunk
                std::vector<BYTE> chunk(buffer.begin() + header_pos, buffer.begin() + header_pos + chunk_size);
                auto streamEntries = ParseShellLinkFromStream(chunk, filePath, L"Custom");
                std::lock_guard<std::mutex> lock(entriesMutex);
                allEntries.insert(allEntries.end(), streamEntries.begin(), streamEntries.end());
            }

            offset = next_pos;
        }
    }

    std::vector<std::wstring> FindJumplistFiles() {
        std::vector<std::wstring> jumplistFiles;
        wchar_t profilesDir[MAX_PATH];

        if (GetEnvironmentVariableW(L"USERPROFILE", profilesDir, MAX_PATH)) {
            std::wstring automaticDir = std::wstring(profilesDir) + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
            std::wstring customDir = std::wstring(profilesDir) + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";

            WIN32_FIND_DATAW findData;
            HANDLE hFind = FindFirstFileW((automaticDir + L"\\*.automaticDestinations-ms").c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        jumplistFiles.push_back(automaticDir + L"\\" + findData.cFileName);
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }

            hFind = FindFirstFileW((customDir + L"\\*.customDestinations-ms").c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        jumplistFiles.push_back(customDir + L"\\" + findData.cFileName);
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
        }

        return jumplistFiles;
    }

    std::wstring GetModuleDirectory() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        PathRemoveFileSpecW(path);
        return path;
    }

    void ExportToCSV(const std::vector<JumplistEntry>& entries, const std::wstring& outputPath) {
        std::ofstream csvFile(outputPath);
        if (!csvFile.is_open()) {
            std::wcerr << L"Failed to create output file: " << outputPath << std::endl;
            return;
        }

        csvFile << "Creation Time,Access Time,Write Time,Name,Path,Signature,Trusted,SHA256,File Size,Jumplist File,Entry Type,Lnk Path,Jumplist Timestamp,Title,AppID,Arguments,Working Dir,Icon Path,Icon Index\n";

        for (const auto& entry : entries) {
            std::wstring fileName = GetFileNameFromPath(entry.path);
            std::wstring fileExt = GetFileExtension(entry.path);
            std::wstring fileSizeStr = (entry.fileSize >= 0) ? std::to_wstring(entry.fileSize) : L"N/A";

            csvFile << "\"" << WideToUTF8(GetSystemTimeString(entry.creationTime)) << "\","
                << "\"" << WideToUTF8(GetSystemTimeString(entry.accessTime)) << "\","
                << "\"" << WideToUTF8(GetSystemTimeString(entry.writeTime)) << "\","
                << "\"" << WideToUTF8(fileName) << "\","
                << "\"" << WideToUTF8(entry.path) << "\","
                << "\"" << WideToUTF8(entry.signatureStatus) << "\","
                << "\"" << WideToUTF8(entry.trusted) << "\","
                << "\"" << WideToUTF8(entry.sha256) << "\","
                << "\"" << WideToUTF8(fileSizeStr) << "\","
                << "\"" << WideToUTF8(entry.jumplistFile) << "\","
                << "\"" << WideToUTF8(entry.entryType) << "\","
                << "\"" << WideToUTF8(entry.lnkPath) << "\","
                << "\"" << WideToUTF8(GetSystemTimeString(entry.jumplistTimestamp)) << "\","
                << "\"" << WideToUTF8(entry.title) << "\","
                << "\"" << WideToUTF8(entry.appId) << "\","
                << "\"" << WideToUTF8(entry.arguments) << "\","
                << "\"" << WideToUTF8(entry.workingDir) << "\","
                << "\"" << WideToUTF8(entry.iconPath) << "\","
                << entry.iconIndex << "\n";
        }

        csvFile.close();
        std::wcout << L"Exported " << entries.size() << L" entries to " << outputPath << std::endl;
    }

    std::vector<JumplistEntry> ParseAllJumpLists() {
        std::vector<JumplistEntry> allEntries;
        CoInitializeEx(NULL, COINIT_MULTITHREADED); // Use multi-threaded COM model

        std::vector<std::wstring> jumplistFiles = FindJumplistFiles();
        if (jumplistFiles.empty()) {
            std::wcerr << L"No jumplist files found. Make sure you're running as administrator." << std::endl;
            CoUninitialize();
            return allEntries;
        }

        std::vector<std::thread> threads;
        unsigned int threadCount = (std::max)(1U, std::thread::hardware_concurrency());
        size_t batchSize = std::max<size_t>(1, jumplistFiles.size() / threadCount);

        for (size_t i = 0; i < jumplistFiles.size(); i += batchSize) {
            size_t endIndex = std::min<size_t>(i + batchSize, jumplistFiles.size());
            for (size_t j = i; j < endIndex; ++j) {
                const std::wstring& file = jumplistFiles[j];
                if (file.find(L".automaticDestinations-ms") != std::wstring::npos) {
                    threads.emplace_back(ParseAutomaticDestinationsThread, file, std::ref(allEntries));
                }
                else if (file.find(L".customDestinations-ms") != std::wstring::npos) {
                    threads.emplace_back(ParseCustomDestinationsThread, file, std::ref(allEntries));
                }
            }
        }

        for (auto& t : threads) {
            t.join();
        }

        // Deduplicate by path
        std::set<std::string> seenPaths;
        std::vector<JumplistEntry> uniqueEntries;
        for (const auto& entry : allEntries) {
            std::string path = WideToUTF8(entry.path);
            if (seenPaths.find(path) == seenPaths.end()) {
                seenPaths.insert(path);
                uniqueEntries.push_back(entry);
            }
        }

        std::wstring outputDir = GetModuleDirectory();
        std::wstring jumplistOutputPath = outputDir + L"\\Jumplists.csv";

        ExportToCSV(uniqueEntries, jumplistOutputPath);

        CoUninitialize();
        return allEntries;
    }
}