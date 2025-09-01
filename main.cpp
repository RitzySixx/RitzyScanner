#include <iostream>
#include "RegistryParser.h"
#include "ProcessScanner.h"
#include "JumpListParser.h"
#include "ServiceScanner.h"

int main() {
    std::cout << "=== Starting Forensic Scanner ===\n";
    // Run Registry Parser
    std::cout << "\n[1/4] Running Registry Parser...\n";
    auto registryResults = RegistryParser::ParseAllRegistry();
    std::cout << " Found " << registryResults.size() << " registry entries\n";
    // Run Process Scanner
    std::cout << "\n[2/4] Running Process Scanner...\n";
    auto processResults = ProcessScanner::ScanAllProcesses();
    std::cout << " Found " << processResults.size() << " file references in process memory\n";
    // Run Jump List Parser
    std::cout << "\n[3/4] Running Jump List Parser...\n";
    auto jumpListResults = JumpListParser::ParseAllJumpLists();
    std::cout << " Found " << jumpListResults.size() << " jump list entries\n";
    // Run Service Checker
    std::cout << "\n[4/4] Checking Key Services...\n";
    auto serviceResults = ServiceScanner::CheckServices();
    std::cout << " Service scan complete. Results saved to Services.csv\n";
    std::cout << "\n=== Forensic Scan Complete ===\n";
    std::cout << "Results saved to:\n";
    std::cout << " - BAM.csv\n";
    std::cout << " - CompatibilityAssistant.csv\n";
    std::cout << " - MuiCache.csv\n";
    std::cout << " - ShellNoRoamMUICache.csv\n";
    std::cout << " - ProcessMemoryScan_<timestamp>.csv\n";
    std::cout << " - Automatic-Jumplists.csv\n";
    std::cout << " - Custom-Jumplists.csv\n";
    std::cout << " - Services.csv\n";
    system("pause");
    return 0;
}