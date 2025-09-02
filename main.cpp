#include <iostream>
#include "RegistryParser.h"
#include "ProcessScanner.h"
#include "JumpListParser.h"
#include "ServiceScanner.h"
#include "DirectFinds.h"

int main() {
    std::cout << "=== Starting Forensic Scanner ===\n";
    // Run Registry Parser
    std::cout << "\n[1/5] Running Registry Parser...\n";
    auto registryResults = RegistryParser::ParseAllRegistry();
    std::cout << " Found " << registryResults.size() << " registry entries\n";
    // Run Process Scanner
    std::cout << "\n[2/5] Running Process Scanner...\n";
    auto processResults = ProcessScanner::ScanAllProcesses();
    std::cout << " Found " << processResults.size() << " file references in process memory\n";
    // Run Jump List Parser
    std::cout << "\n[3/5] Running Jump List Parser...\n";
    auto jumpListResults = JumpListParser::ParseAllJumpLists();
    std::cout << " Found " << jumpListResults.size() << " jump list entries\n";
    // Run Service Checker
    std::cout << "\n[4/5] Checking Key Services...\n";
    auto serviceResults = ServiceScanner::CheckServices();
    std::cout << " Service scan complete. Results saved to Services.csv\n";
    // Run Direct Finds Scanner
    std::cout << "\n[5/5] Running Direct Finds Scanner (checking FiveM and GTA V folders)...\n";
    auto directResults = DirectFinds::ScanDirectFinds();
    std::cout << " Found " << directResults.size() << " direct findings\n";
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
    std::cout << " - DirectFinds.csv\n";
    system("pause");
    return 0;
}