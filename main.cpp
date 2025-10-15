#include <iostream>
#include "RegistryParser.h"
#include "ProcessScanner.h"
#include "JumpListParser.h"
#include "ServiceScanner.h"
#include "PcaAppLaunch.h"
#include "DirectFinds.h"
#include "PrefetchAnalyzer.h"
#include "EnhancedLogger.h"

int main() {
    std::cout << "=== Starting Enhanced Forensic Scanner ===\n";

    // Initialize enhanced logging system
    EnhancedLogger::InitializeGlobalTracking();
    std::cout << "Enhanced logging system initialized for problematic entries only\n";

    // Run Registry Parser
    std::cout << "\n[1/6] Running Registry Parser...\n";
    auto registryResults = RegistryParser::ParseAllRegistry();
    std::cout << " Found " << registryResults.size() << " registry entries\n";
    // Run Process Scanner
    std::cout << "\n[2/6] Running Process Scanner...\n";
    auto processResults = ProcessScanner::ScanAllProcesses();
    std::cout << " Found " << processResults.size() << " file references in process memory\n";
    // Run Jump List Parser
    std::cout << "\n[3/6] Running Jump List Parser...\n";
    auto jumpListResults = JumpListParser::ParseAllJumpLists();
    std::cout << " Found " << jumpListResults.size() << " jump list entries\n";
    // Run Service Checker
    std::cout << "\n[4/6] Checking Key Services...\n";
    auto serviceResults = ServiceScanner::CheckServices();
    std::cout << " Service scan complete. Results saved to Services.csv\n";
    // Run PCA App Launch Parser
    std::cout << "\n[5/6] Running PCA App Launch Parser...\n";
    auto pcaResults = PcaAppLaunch::ParsePcaAppLaunch();
    std::cout << " Found " << pcaResults.size() << " PCA app launch entries\n";
    // Run Prefetch Analyzer
    std::cout << "\n[6/7] Running Prefetch Analyzer...\n";
    PrefetchAnalyzer analyzer;
    if (!analyzer.CheckAdminPrivileges()) {
        std::cout << " Warning: Not running as administrator. Some features may not work.\n";
    }
    analyzer.AnalyzePrefetchFiles("C:\\Windows\\Prefetch");
    analyzer.LogToCSV("prefetch_analysis.csv");
    std::cout << " Prefetch analysis complete. Results saved to prefetch_analysis.csv\n";
    // Run Direct Finds Scanner
    std::cout << "\n[7/7] Running Direct Finds Scanner (checking FiveM and GTA V folders)...\n";
    auto directResults = DirectFinds::ScanDirectFinds();
    std::cout << " Found " << directResults.size() << " direct findings\n";
    std::cout << "\n=== Enhanced Forensic Scan Complete ===\n";
    std::cout << "Results saved to:\n";
    std::cout << " - Registry.csv\n";
    std::cout << " - ProcessMemoryScan_<timestamp>.csv\n";
    std::cout << " - Jumplists.csv\n";
    std::cout << " - Services.csv\n";
    std::cout << " - PcaAppLaunch.csv\n";
    std::cout << " - prefetch_analysis.csv\n";
    std::cout << " - DirectFinds.csv\n";
    std::cout << "\nEnhanced Logging:\n";
    std::cout << " - Problematic entries logged to SentryX server\n";
    std::cout << " - Detailed local logs available in current directory\n";
    system("pause");
    return 0;
}