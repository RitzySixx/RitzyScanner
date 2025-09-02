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

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace JumpListParser {
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
        DWORD attrs = GetFileAttributesW(filePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            return "Deleted"; // file missing
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

        // Close state
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

        if (lStatus == ERROR_SUCCESS) {
            return "Valid (Authenticode)";
        }

        // Check catalog signature
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
        if (signatureStatus == "Deleted") {
            return ""; // deleted → leave blank
        }

        if (signatureStatus == "Invalid" || signatureStatus == "Unsigned") {
            return "Untrusted"; // no digital signature
        }

        // File is signed, verify trust
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

        if (lStatus == ERROR_SUCCESS) {
            return "Trusted";
        }

        return "Untrusted";
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

    std::vector<JumplistEntry> ParseShellLink(const std::wstring& lnkPath, const std::wstring& jumplistFile, const std::wstring& entryType) {
        std::vector<JumplistEntry> entries;

        CComPtr<IShellLinkW> psl;
        if (FAILED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl))) {
            return entries;
        }

        CComPtr<IPersistFile> ppf;
        if (FAILED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
            return entries;
        }

        if (FAILED(ppf->Load(lnkPath.c_str(), STGM_READ))) {
            return entries;
        }

        CComPtr<IPropertyStore> pPropStore;
        if (FAILED(psl->QueryInterface(IID_IPropertyStore, (void**)&pPropStore))) {
            return entries;
        }

        JumplistEntry entry;
        entry.jumplistFile = jumplistFile;
        entry.entryType = entryType;
        entry.lnkPath = lnkPath;

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
                CloseHandle(hFile);
            }
        }

        HANDLE hFile = CreateFileW(jumplistFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            FILETIME ftCreate, ftAccess, ftWrite;
            if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                entry.jumplistTimestamp = ftWrite;
            }
            CloseHandle(hFile);
        }

        if (!entry.path.empty()) {
            // Check the file signature (Authenticode / Catalog / Deleted)
            std::string sigStatus = CheckFileSignature(entry.path);
            entry.signatureStatus = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sigStatus);

            // Determine trust
            std::string trusted;
            if (sigStatus == "Deleted") {
                trusted = ""; // deleted → leave blank
            }
            else if (sigStatus == "Invalid" || sigStatus == "Unsigned") {
                trusted = "Untrusted"; // no digital signature
            }
            else {
                trusted = IsSignatureTrusted(sigStatus, entry.path); // signed → check trust
            }

            entry.trusted = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(trusted);
        }
        else {
            entry.signatureStatus = L"N/A";
            entry.trusted = L"";
        }

        entries.push_back(entry);
        return entries;
    }

    std::vector<JumplistEntry> ParseAutomaticDestinations(const std::wstring& filePath) {
        std::vector<JumplistEntry> entries;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return entries;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return entries;
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hFile);
            return entries;
        }
        CloseHandle(hFile);

        CComPtr<IStorage> pStorage;
        if (FAILED(StgOpenStorageEx(filePath.c_str(), STGM_READ | STGM_SHARE_DENY_WRITE,
            STGFMT_STORAGE, 0, NULL, NULL, IID_IStorage, (void**)&pStorage))) {
            return entries;
        }

        CComPtr<IEnumSTATSTG> pEnum;
        if (FAILED(pStorage->EnumElements(0, NULL, 0, &pEnum))) {
            return entries;
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
                ULONG bytesRead = 0;
                std::vector<BYTE> streamBuffer(stat.cbSize.LowPart);
                if (SUCCEEDED(pStream->Read(streamBuffer.data(), stat.cbSize.LowPart, &bytesRead))) {
                    wchar_t tempPath[MAX_PATH];
                    GetTempPathW(MAX_PATH, tempPath);
                    wchar_t tempFile[MAX_PATH];
                    GetTempFileNameW(tempPath, L"jmp", 0, tempFile);

                    HANDLE hTempFile = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hTempFile != INVALID_HANDLE_VALUE) {
                        DWORD bytesWritten;
                        WriteFile(hTempFile, streamBuffer.data(), bytesRead, &bytesWritten, NULL);
                        CloseHandle(hTempFile);

                        auto streamEntries = ParseShellLink(tempFile, filePath, L"Automatic");
                        entries.insert(entries.end(), streamEntries.begin(), streamEntries.end());
                        DeleteFileW(tempFile);
                    }
                }
            }

            CoTaskMemFree(stat.pwcsName);
        }

        return entries;
    }

    std::vector<JumplistEntry> ParseCustomDestinations(const std::wstring& filePath) {
        std::vector<JumplistEntry> entries;

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return entries;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return entries;
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hFile);
            return entries;
        }
        CloseHandle(hFile);

        size_t offset = 0;
        while (offset < buffer.size()) {
            if (offset + 0x4C > buffer.size()) break;

            if (buffer[offset] == 0x4C && buffer[offset + 1] == 0x00 &&
                buffer[offset + 2] == 0x00 && buffer[offset + 3] == 0x00) {

                size_t nextOffset = offset + 0x4C;
                while (nextOffset + 4 < buffer.size()) {
                    if (buffer[nextOffset] == 0x4C && buffer[nextOffset + 1] == 0x00 &&
                        buffer[nextOffset + 2] == 0x00 && buffer[nextOffset + 3] == 0x00) {
                        break;
                    }
                    nextOffset++;
                }

                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                wchar_t tempFile[MAX_PATH];
                GetTempFileNameW(tempPath, L"jmp", 0, tempFile);

                HANDLE hTempFile = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hTempFile != INVALID_HANDLE_VALUE) {
                    DWORD bytesWritten;
                    WriteFile(hTempFile, &buffer[offset], (DWORD)(nextOffset - offset), &bytesWritten, NULL);
                    CloseHandle(hTempFile);

                    auto streamEntries = ParseShellLink(tempFile, filePath, L"Custom");
                    entries.insert(entries.end(), streamEntries.begin(), streamEntries.end());
                    DeleteFileW(tempFile);
                }

                offset = nextOffset;
            }
            else {
                offset++;
            }
        }

        return entries;
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

    void ExportToCSV(const std::vector<JumplistEntry>& entries, const std::wstring& outputPath, bool isCustom) {
        std::ofstream csvFile(outputPath);
        if (!csvFile.is_open()) {
            std::wcerr << L"Failed to create output file: " << outputPath << std::endl;
            return;
        }

        if (isCustom) {
            csvFile << "Jumplist Timestamp,Creation Time,Access Time,Write Time,Name,Title,Path,Signature,Trusted,Arguments,Icon Path,Jumplist File,Entry Type,Lnk Path\n";
        }
        else {
            csvFile << "Jumplist Timestamp,Creation Time,Access Time,Write Time,Name,Path,Signature,Trusted,Jumplist File,Entry Type,Lnk Path\n";
        }

        for (const auto& entry : entries) {
            std::wstring fileName = GetFileNameFromPath(entry.path);
            std::wstring fileExt = GetFileExtension(entry.path);

            if (isCustom) {
                csvFile << "\"" << WideToUTF8(GetSystemTimeString(entry.jumplistTimestamp)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.creationTime)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.accessTime)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.writeTime)) << "\","
                    << "\"" << WideToUTF8(fileName) << "\","
                    << "\"" << WideToUTF8(entry.title) << "\","
                    << "\"" << WideToUTF8(entry.path) << "\","
                    << "\"" << WideToUTF8(entry.signatureStatus) << "\","
                    << "\"" << WideToUTF8(entry.trusted) << "\","
                    << "\"" << WideToUTF8(entry.arguments) << "\","
                    << "\"" << WideToUTF8(entry.iconPath) << "\","
                    << "\"" << WideToUTF8(entry.jumplistFile) << "\","
                    << "\"" << WideToUTF8(entry.entryType) << "\","
                    << "\"" << WideToUTF8(entry.lnkPath) << "\"\n";
            }
            else {
                csvFile << "\"" << WideToUTF8(GetSystemTimeString(entry.jumplistTimestamp)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.creationTime)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.accessTime)) << "\","
                    << "\"" << WideToUTF8(GetSystemTimeString(entry.writeTime)) << "\","
                    << "\"" << WideToUTF8(fileName) << "\","
                    << "\"" << WideToUTF8(entry.path) << "\","
                    << "\"" << WideToUTF8(entry.signatureStatus) << "\","
                    << "\"" << WideToUTF8(entry.trusted) << "\","
                    << "\"" << WideToUTF8(entry.jumplistFile) << "\","
                    << "\"" << WideToUTF8(entry.entryType) << "\","
                    << "\"" << WideToUTF8(entry.lnkPath) << "\"\n";
            }
        }

        csvFile.close();
        std::wcout << L"Exported " << entries.size() << L" entries to " << outputPath << std::endl;
    }

    std::vector<JumplistEntry> ParseAllJumpLists() {
        std::vector<JumplistEntry> allEntries;
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

        std::vector<std::wstring> jumplistFiles = FindJumplistFiles();
        if (jumplistFiles.empty()) {
            std::wcerr << L"No jumplist files found. Make sure you're running as administrator." << std::endl;
            CoUninitialize();
            return allEntries;
        }

        // Blue for checking each jumplist file
        for (const auto& jumplistFile : jumplistFiles) {
            // Set blue text
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
            std::wcout << L"Checking jumplist: " << jumplistFile << L" ...\n";
            // Reset color
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);

            if (jumplistFile.find(L".automaticDestinations-ms") != std::wstring::npos) {
                auto entries = ParseAutomaticDestinations(jumplistFile);
                allEntries.insert(allEntries.end(), entries.begin(), entries.end());
            }
            else if (jumplistFile.find(L".customDestinations-ms") != std::wstring::npos) {
                auto entries = ParseCustomDestinations(jumplistFile);
                allEntries.insert(allEntries.end(), entries.begin(), entries.end());
            }
        }

        std::wstring outputDir = GetModuleDirectory();
        std::wstring automaticOutputPath = outputDir + L"\\Automatic-Jumplists.csv";
        std::wstring customOutputPath = outputDir + L"\\Custom-Jumplists.csv";

        std::vector<JumplistEntry> automaticEntries, customEntries;
        for (const auto& entry : allEntries) {
            if (entry.entryType == L"Automatic") {
                automaticEntries.push_back(entry);
            }
            else {
                customEntries.push_back(entry);
            }
        }

        ExportToCSV(automaticEntries, automaticOutputPath, false);
        ExportToCSV(customEntries, customOutputPath, true);

        CoUninitialize();
        return allEntries;
    }
}