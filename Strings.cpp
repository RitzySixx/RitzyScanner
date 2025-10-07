#define UNICODE
#define _UNICODE
#include "strings.h"
#include "utils.h"

// Console color management
ConsoleColor::ConsoleColor() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(hConsole, &info);
    originalAttributes = info.wAttributes;
}

ConsoleColor::~ConsoleColor() {
    SetConsoleTextAttribute(hConsole, originalAttributes);
}

void ConsoleColor::setColor(WORD color) {
    SetConsoleTextAttribute(hConsole, color);
}

MemoryScanner::MemoryScanner() {
    InitializeDetections();
}

void MemoryScanner::InitializeDetections() {
    // Helper function to create detection strings with pre-computed versions
    auto makeDetection = [](const std::string& name, const std::string& pattern) {
        std::string patternLower = pattern;
        std::transform(patternLower.begin(), patternLower.end(), patternLower.begin(), ::tolower);

        // Convert to wide string for Unicode detection
        std::wstring patternWide = StringToWide(pattern);

        return DetectionString{ name, pattern, patternLower, patternWide };
        };

    // Explorer.exe detections
    processDetections["explorer.exe"] = {
        makeDetection("Drive Letter A", "file:///A"),
        makeDetection("Drive Letter B", "file:///B"),
        makeDetection("Drive Letter F", "file:///F"),
        makeDetection("Drive Letter G", "file:///G"),
        makeDetection("Drive Letter H", "file:///H"),
        makeDetection("Drive Letter I", "file:///I"),
        makeDetection("Drive Letter J", "file:///J"),
        makeDetection("Drive Letter K", "file:///K"),
        makeDetection("Drive Letter L", "file:///L"),
        makeDetection("Drive Letter M", "file:///M"),
        makeDetection("Drive Letter N", "file:///N"),
        makeDetection("Drive Letter Q", "file:///Q"),
        makeDetection("Drive Letter P", "file:///P"),
        makeDetection("Drive Letter O", "file:///O"),
        makeDetection("Drive Letter R", "file:///R"),
        makeDetection("Drive Letter S", "file:///S"),
        makeDetection("Drive Letter T", "file:///T"),
        makeDetection("Drive Letter U", "file:///U"),
        makeDetection("Drive Letter V", "file:///V"),
        makeDetection("Drive Letter W", "file:///W"),
        makeDetection("Drive Letter X", "file:///X"),
        makeDetection("Drive Letter Y", "file:///Y"),
        makeDetection("Drive Letter Z", "file:///Z"),
        makeDetection("RedEngine", "settings.cock"),
        makeDetection("TdPremium", "tdpremium.exe"),
        makeDetection("TdPremium 2", "tdloader.exe"),
        makeDetection("TZX", "TZX.zip"),
        makeDetection("TZ", "TZ.zip"),
        makeDetection("fast_connect_vehicle", "fast_connect_vehicle.zip"),
        makeDetection("fast_ladder", "fast_ladder.zip"),
        makeDetection("no_recoil", "no_recoil.rpf"),
        makeDetection("no_fall_damage", "no_fall_damage.rpf"),
        makeDetection("magic_bullet", "magic_bullet.rpf"),
        makeDetection("pedaccuracy (banla)", "pedaccuracy.meta"),
        makeDetection("handling_modifier", "handling_modifier.rpf"),
        makeDetection("10x_Damage_Boost", "10x_Damage_Boost.rpf"),
        makeDetection("1.5x_Damage_Boost", "1.5x_Damage_Boost.rpf"),
        makeDetection("Fast_Run", "Fast_Run.rpf"),
        makeDetection("snrsz_dron", "snrsz_dron.rpf"),
        makeDetection("remove_roll", "remove_roll.zip"),
        makeDetection("curseMenu", "curseMenu.lua"),
        makeDetection("Cleaner", "Cleaner.bat"),
        makeDetection("busspawn", "busspawn.lua"),
        makeDetection("araclarbozs", "araclarbozs.lua"),
        makeDetection("PickUpProp", "PickUpProp.lua"),
        makeDetection("fivemcrash", "fivemcrash.exe"),
        makeDetection("Bypass", "Bypass.lua"),
        makeDetection("BypassCleaner", "leaksggbypass.bat"),
        makeDetection("SeteBypass", "SeteBypass.zip"),
        makeDetection("StoppedMain", "StoppedMain.rar"),
        makeDetection("NoStaminaZpShop", "boost.rpf"),
        makeDetection("strafemethod (macrolu)", "dreyko.mgp"),
        makeDetection("Bigger_Hitbox", "Bigger_Hitbox.rar"),
        makeDetection("NO_VDM", "NO_VDM.rar"),
        makeDetection("apPistolModifier", "apPistolModifier.rar"),
        makeDetection("FastLadder (hizlimerdiven)", "ladders-fly.rar"),
        makeDetection("HEADsoftAim", "HEADsoftAim_.rpf"),
        makeDetection("ZC-softAim", "ZC-softAim.rpf"),
        makeDetection("Cheatleaks22", "Cheatleaks22.rar"),
        makeDetection("tec9_pistol_all_gun_tek_atar_gg", "tec9_pistol_all_gun_tek_atar_gg.eaxpack.zip"),
        makeDetection("nofalldamagenostamina", "nofalldamagenostamina.rpf"),
        makeDetection("sınırsızdrone", "sınırsızdrone.rpf"),
        makeDetection("fast car", "fast car.rpf"),
        makeDetection("godmode", "godmode.rar"),
        makeDetection("noroll", "noroll.rpf"),
        makeDetection("bulletpencar", "bulletpencar.rpf"),
        makeDetection("fastreload", "fastreload.rpf"),
        makeDetection("onepunch", "onepunch.rpf"),
        makeDetection("Car Fast connect foxen", "foxen_fast_connect.zip"),
        makeDetection("Car Fast connect foxen", "foxen_fast_connect.rpf"),
        makeDetection("Fast Ladder (hizli merdiven) Foxen", "foxen_fast_ladder.zip"),
        makeDetection("Fast Ladder (hizli merdiven) Foxen", "foxen_fast_ladder.rpf"),
        makeDetection("foxen_fast_reload", "foxen_fast_reload.zip"),
        makeDetection("foxen_fast_reload", "foxen_fast_reload.rpf"),
        makeDetection("foxen_infinity_ammo", "foxen_infinity_ammo.zip"),
        makeDetection("foxen_infinity_ammo", "foxen_infinity_ammo.rpf"),
        makeDetection("foxen_master_skills", "foxen_master_skills.zip"),
        makeDetection("foxen_master_skills", "foxen_master_skills.rpf"),
        makeDetection("foxen_bullet_disintegration", "foxen_bullet_disintegration.zip"),
        makeDetection("foxen_bullet_disintegration", "foxen_bullet_disintegration.rpf"),
        makeDetection("foxen_low_damage", "foxen_low_damage.rpf"),
        makeDetection("foxen_low_damage", "foxen_low_damage.zip"),
        makeDetection("foxen_god_mode", "foxen_god_mode.zip"),
        makeDetection("foxen_god_mode", "foxen_god_mode.rpf"),
        makeDetection("foxen_snrsz_drone", "foxen_snrsz_drone.zip"),
        makeDetection("foxen_snrsz_drone", "foxen_snrsz_drone.rpf"),
        makeDetection("foxen_1.5x_damage_boost", "foxen_1.5x_damage_boost.zip"),
        makeDetection("foxen_1.5x_damage_boost", "foxen_1.5x_damage_boost.rpf"),
        makeDetection("foxen_no_vdm", "foxen_no_vdm.zip"),
        makeDetection("foxen_no_vdm", "foxen_no_vdm.rpf"),
        makeDetection("foxen_no_stamina", "foxen_no_stamina.zip"),
        makeDetection("foxen_no_stamina", "foxen_no_stamina.rpf"),
        makeDetection("foxen_no_recoil", "foxen_no_recoil.zip"),
        makeDetection("foxen_no_recoil", "foxen_no_recoil.rpf"),
        makeDetection("foxen_magic_bullet", "foxen_magic_bullet.zip"),
        makeDetection("foxen_magic_bullet", "foxen_magic_bullet.rpf"),
        makeDetection("foxen_handling_modifier", "foxen_handling_modifier.zip"),
        makeDetection("foxen_handling_modifier", "foxen_handling_modifier.rpf"),
        makeDetection("foxen_fast_run", "foxen_fast_run.zip"),
        makeDetection("foxen_fast_run", "foxen_fast_run.rpf"),
        makeDetection("foxen_no_fall_damage", "foxen_no_fall_damage.zip"),
        makeDetection("foxen_no_fall_damage", "foxen_no_fall_damage.rpf"),
        makeDetection("foxen_no_wall", "foxen_no_wall.zip"),
        makeDetection("foxen_no_wall", "foxen_no_wall.rpf"),
        makeDetection("foxen_remove_roll", "foxen_remove_roll.zip"),
        makeDetection("foxen_remove_roll", "foxen_remove_roll.rpf"),
        makeDetection("gg.fivemcheat spoofer", "paytr.exe"),
        makeDetection("RPF Spawn Armor", "ZC-Loadout")
    };

    // PcaSvc detections
    processDetections["PcaSvc"] = {
        makeDetection("Gosth", "0x4477000"),
        makeDetection("Traceless", "0xd65000"),
        makeDetection("Wexize Bypass", "0xac424d0"),
        makeDetection("MrCheat", "0x67b000"),
        makeDetection("88Cheat", "0x1d7b000"),
        makeDetection("Macho", "0x4304000")
    };

    // DPS detections
    processDetections["DPS"] = {
        makeDetection("Gosth", "2025/03/09:21:24:52"),
        makeDetection("TZ Project", "2025/01/14:11:41:43"),
        makeDetection("Traceless", "2025/06/24:16:39:02"),
        makeDetection("CalienteBypass", "2025/05/09:16:48:44")
    };

    // Dnscache detections
    processDetections["Dnscache"] = {
        makeDetection("Skript", "Skript.gg"),
        makeDetection("Gosth", "pedrin.cc"),
        makeDetection("HX Cheats", "api.hxcheats.com"),
        makeDetection("HX Cheats", "kzoem.hxcheats.com"),
        makeDetection("TZ Project", "tzproject.com"),
        makeDetection("TZ Project", "api.tzproject.com")
    };
}

// Utility functions for string conversion
std::wstring MemoryScanner::StringToWide(const std::string& str) {
    int count = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

std::string MemoryScanner::WideToString(const std::wstring& wstr) {
    int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
}

bool MemoryScanner::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

std::string MemoryScanner::ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::wstring MemoryScanner::ToLower(const std::wstring& wstr) {
    std::wstring result = wstr;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

// Check if pattern meets minimum length requirement
bool MemoryScanner::MeetsMinimumLength(const std::string& pattern) {
    return pattern.length() >= 5;
}

// Fast case-insensitive search for ASCII
bool MemoryScanner::ContainsPatternFast(const std::string& contentLower, const DetectionString& detection) {
    if (!MeetsMinimumLength(detection.pattern)) return false;
    return contentLower.find(detection.patternLower) != std::string::npos;
}

// Unicode-aware search
bool MemoryScanner::ContainsPatternUnicode(const std::wstring& contentWideLower, const DetectionString& detection) {
    if (!MeetsMinimumLength(detection.pattern)) return false;

    // Search for wide string pattern
    if (contentWideLower.find(detection.patternWide) != std::wstring::npos) {
        return true;
    }

    // Also search for ASCII pattern in wide string (for mixed content)
    std::wstring asciiPatternWide = StringToWide(detection.patternLower);
    return contentWideLower.find(asciiPatternWide) != std::wstring::npos;
}

// Extended Unicode detection for various encodings
bool MemoryScanner::ContainsExtendedUnicode(const std::string& content, const DetectionString& detection) {
    if (!MeetsMinimumLength(detection.pattern)) return false;

    // Check for UTF-16 LE
    std::wstring utf16Pattern = detection.patternWide;
    for (size_t i = 0; i < content.size() - utf16Pattern.size() * 2; ++i) {
        bool match = true;
        for (size_t j = 0; j < utf16Pattern.size(); ++j) {
            wchar_t patternChar = utf16Pattern[j];
            wchar_t contentChar = *reinterpret_cast<const wchar_t*>(&content[i + j * 2]);
            if (patternChar != contentChar) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }

    return false;
}

// Check if memory region is likely to contain strings (for explorer.exe)
bool MemoryScanner::IsRegionStringLike(const std::vector<BYTE>& buffer, size_t bytesRead) {
    size_t printableCount = 0;
    for (size_t i = 0; i < bytesRead; ++i) {
        if ((buffer[i] >= 32 && buffer[i] <= 126) || buffer[i] == 0) {
            printableCount++;
        }
    }
    // Consider region string-like if at least 50% of bytes are printable ASCII or null
    return (printableCount >= bytesRead / 2);
}

DWORD MemoryScanner::GetServicePID(const std::string& serviceName) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        std::cout << "Failed to open SCManager for " << serviceName << ": " << GetLastError() << std::endl;
        return 0;
    }

    SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        std::cout << "Failed to open service " << serviceName << ": " << GetLastError() << std::endl;
        CloseServiceHandle(scManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    DWORD pid = 0;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
        sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        pid = ssp.dwProcessId;
    }
    else {
        std::cout << "Failed to query service status for " << serviceName << ": " << GetLastError() << std::endl;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return pid;
}

DWORD MemoryScanner::GetExplorerPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::wstring wProcessName(pe.szExeFile);
            std::string processName(wProcessName.begin(), wProcessName.end());
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            if (processName == "explorer.exe") {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        std::cout << "Failed to enumerate processes for explorer.exe: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}

std::string MemoryScanner::GetProcessName(DWORD pid) {
    if (pid == 0) return "Unknown";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open process " << pid << ": " << GetLastError() << std::endl;
        return "Unknown";
    }

    char processName[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string result = "Unknown";

    if (GetProcessImageFileNameA(hProcess, processName, size) > 0) {
        result = processName;
        size_t lastSlash = result.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            result = result.substr(lastSlash + 1);
        }
    }
    else {
        std::cout << "Failed to get process name for PID " << pid << ": " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return result;
}

// Scanning logic for DPS and PcaSvc
std::vector<ScanResult> MemoryScanner::ScanServiceMemory(DWORD pid, const std::string& processType, const std::vector<DetectionString>& detections) {
    std::vector<ScanResult> results;
    std::set<std::string> detectedPatterns; // Track patterns already found

    if (pid == 0) {
        std::cout << "Invalid PID for " << processType << std::endl;
        return results;
    }

    std::string processName = GetProcessName(pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess) {
        std::cout << "Failed to open process " << processName << " (PID: " << pid << "): " << GetLastError() << std::endl;
        return results;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T offset = 0;
    const SIZE_T MAX_REGION_SIZE = 100 * 1024 * 1024; // 100MB for services

    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize <= MAX_REGION_SIZE && mbi.RegionSize > 0) {

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) || bytesRead == 0) {
                std::cout << "Failed to read memory at " << mbi.BaseAddress << " for " << processName << ": " << GetLastError() << std::endl;
                offset += mbi.RegionSize;
                continue;
            }

            std::string content(buffer.begin(), buffer.begin() + bytesRead);

            // Convert to lowercase for ASCII search
            std::string contentLower = ToLower(content);

            // Convert to wide string for Unicode search
            std::wstring contentWide = std::wstring(content.begin(), content.end());
            std::wstring contentWideLower = ToLower(contentWide);

            // Check all patterns against the content
            for (const auto& detection : detections) {
                if (detectedPatterns.find(detection.name) != detectedPatterns.end()) {
                    continue;
                }

                bool found = false;
                std::string matchType = "ASCII";

                if (ContainsPatternFast(contentLower, detection)) {
                    found = true;
                }
                else if (ContainsPatternUnicode(contentWideLower, detection)) {
                    found = true;
                    matchType = "Unicode";
                }
                else if (ContainsExtendedUnicode(content, detection)) {
                    found = true;
                    matchType = "Extended Unicode";
                }

                if (found) {
                    results.push_back({ detection.name, processType, pid, detection.pattern, matchType });
                    detectedPatterns.insert(detection.name);
                }
            }
        }

        offset += mbi.RegionSize;
        if (offset == 0) break; // Overflow protection
    }

    CloseHandle(hProcess);
    return results;
}

// Optimized scanning logic for explorer.exe
std::vector<ScanResult> MemoryScanner::ScanExplorerMemory(DWORD pid, const std::string& processType, const std::vector<DetectionString>& detections) {
    std::vector<ScanResult> results;
    std::set<std::string> detectedPatterns; // Track patterns already found

    if (pid == 0) {
        std::cout << "Invalid PID for " << processType << std::endl;
        return results;
    }

    std::string processName = GetProcessName(pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess) {
        std::cout << "Failed to open process " << processName << " (PID: " << pid << "): " << GetLastError() << std::endl;
        return results;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T offset = 0;
    const SIZE_T MAX_REGION_SIZE = 10 * 1024 * 1024; // 10MB for explorer.exe

    // Function to scan a subset of patterns
    auto scanPatterns = [&](const std::string& content, const std::string& contentLower,
        const std::wstring& contentWideLower, const std::vector<DetectionString>& patterns,
        size_t start, size_t end) -> std::vector<ScanResult> {
            std::vector<ScanResult> localResults;
            for (size_t i = start; i < end && i < patterns.size(); ++i) {
                const auto& detection = patterns[i];
                if (detectedPatterns.find(detection.name) != detectedPatterns.end()) {
                    continue;
                }

                bool found = false;
                std::string matchType = "ASCII";

                if (ContainsPatternFast(contentLower, detection)) {
                    found = true;
                }
                else if (ContainsPatternUnicode(contentWideLower, detection)) {
                    found = true;
                    matchType = "Unicode";
                }
                else if (ContainsExtendedUnicode(content, detection)) {
                    found = true;
                    matchType = "Extended Unicode";
                }

                if (found) {
                    localResults.push_back({ detection.name, processType, pid, detection.pattern, matchType });
                    detectedPatterns.insert(detection.name); // Thread-safe since called within locked section
                }
            }
            return localResults;
        };

    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize <= MAX_REGION_SIZE && mbi.RegionSize > 0) {

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) || bytesRead == 0) {
                std::cout << "Failed to read memory at " << mbi.BaseAddress << " for " << processName << ": " << GetLastError() << std::endl;
                offset += mbi.RegionSize;
                continue;
            }

            // Early termination: Skip non-string-like regions
            if (!IsRegionStringLike(buffer, bytesRead)) {
                offset += mbi.RegionSize;
                continue;
            }

            std::string content(buffer.begin(), buffer.begin() + bytesRead);
            std::string contentLower = ToLower(content); // Cache lowercase
            std::wstring contentWide = std::wstring(content.begin(), content.end());
            std::wstring contentWideLower = ToLower(contentWide); // Cache wide lowercase

            // Parallelize pattern matching
            unsigned int numThreads = std::thread::hardware_concurrency();
            if (numThreads == 0) numThreads = 4; // Fallback
            std::vector<std::future<std::vector<ScanResult>>> futures;
            size_t patternsPerThread = (detections.size() + numThreads - 1) / numThreads;

            for (size_t i = 0; i < detections.size(); i += patternsPerThread) {
                size_t end = (std::min)(i + patternsPerThread, detections.size());
                futures.push_back(std::async(std::launch::async, scanPatterns,
                    content, contentLower, contentWideLower,
                    detections, i, end));
            }

            // Collect results
            for (auto& future : futures) {
                auto threadResults = future.get();
                results.insert(results.end(), threadResults.begin(), threadResults.end());
            }
        }

        offset += mbi.RegionSize;
        if (offset == 0) break; // Overflow protection
    }

    CloseHandle(hProcess);
    return results;
}

std::vector<ScanResult> MemoryScanner::ScanAllProcesses() {
    std::vector<ScanResult> allResults;

    ConsoleColor color;
    color.setColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "Enabling debug privileges..." << std::endl;

    if (!EnableDebugPrivilege()) {
        color.setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "Warning: Could not enable debug privileges. Some processes may not be accessible. Please run as administrator." << std::endl;
    }

    auto startTime = std::chrono::high_resolution_clock::now();

    // Scan each specific process/service
    for (const auto& entry : processDetections) {
        const std::string& processType = entry.first;
        const std::vector<DetectionString>& detections = entry.second;

        color.setColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); // CYAN
        std::cout << "Scanning " << processType << "..." << std::endl;

        DWORD pid = 0;

        if (processType == "explorer.exe") {
            pid = GetExplorerPID();
        }
        else if (processType == "PcaSvc" || processType == "DPS" || processType == "Dnscache") {
            pid = GetServicePID(processType);
        }

        if (pid == 0) {
            color.setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << processType << " not found or not running." << std::endl;
            continue;
        }

        std::vector<ScanResult> results;
        if (processType == "explorer.exe") {
            results = ScanExplorerMemory(pid, processType, detections);
        }
        else {
            results = ScanServiceMemory(pid, processType, detections);
        }

        for (const auto& result : results) {
            allResults.push_back(result);

            color.setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "FOUND " << result.detectionName << " in "
                << result.processName << " (PID: " << result.processId << ") - "
                << result.matchType << std::endl;
            std::cout << "Pattern: " << result.pattern << std::endl;
        }

        if (results.empty()) {
            color.setColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << processType << " scanned - no detections." << std::endl;
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    color.setColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "\nScan completed in " << duration.count() << "ms. Found "
        << allResults.size() << " detection(s)." << std::endl;

    return allResults;
}

std::vector<StringMatch> ScanProcessesAndServicesForStrings() {
    ConsoleColor color;
    color.setColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "=== Advanced Process Memory Scanner ===" << std::endl;
    std::cout << "Features: Unicode, Extended Unicode, Memory Type Filtering" << std::endl;
    std::cout << "Scanning: explorer.exe, PcaSvc, DPS, Dnscache" << std::endl;
    std::cout << "Memory Types: PRIVATE, IMAGE, MAPPED" << std::endl;
    std::cout << "Minimum Pattern Length: 5" << std::endl;
    std::cout << "Starting memory scan..." << std::endl << std::endl;

    MemoryScanner scanner;
    auto results = scanner.ScanAllProcesses();

    std::vector<StringMatch> matches;
    for (const auto& result : results) {
        std::string pName = result.processName;
        if (pName == "PcaSvc") {
            pName = "svchost.exe (pcasvc)";
        }
        else if (pName == "DPS") {
            pName = "svchost.exe (dps)";
        }
        else if (pName == "Dnscache") {
            pName = "svchost.exe (dnscache)";
        }
        matches.push_back({ result.detectionName, pName });
    }

    if (matches.empty()) {
        color.setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "\nNo suspicious patterns detected." << std::endl;
    }
    else {
        color.setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "\n=== SCAN SUMMARY ===" << std::endl;
        for (const auto& match : matches) {
            std::cout << "FOUND: " << match.detectionName << " in "
                << match.processName << std::endl;
        }
    }

    return matches;
}