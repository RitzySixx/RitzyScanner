#include <iostream>
#include <vector>
#include <string>
#include "RegistryParser.h"
#include "ProcessScanner.h"
#include "JumpListParser.h"
#include "ServiceScanner.h"
#include "PcaAppLaunch.h"
#include "DirectFinds.h"
#include "PrefetchAnalyzer.h"
#include "EnhancedLogger.h"
#include "strings.h"
#include "DiscordDownloads.h"

// Structure to hold scan summary
struct ScanSummary {
    std::string scanType;
    int totalEntries;
    int problematicEntries;
    std::string status;
};

int main() {
    std::cout << "===============================================\n";
    std::cout << "    Enhanced Forensic Scanner v2.0\n";
    std::cout << "    Professional Digital Forensics Tool\n";
    std::cout << "===============================================\n\n";

    // Initialize enhanced logging system
    EnhancedLogger::InitializeGlobalTracking();
    std::cout << "[INFO] Logging system initialized\n\n";

    std::vector<ScanSummary> scanResults;

    // Run Registry Parser
    std::cout << "[1/7] Registry Analysis...\n";
    std::cout << "       Scanning system registry for suspicious entries...\n";
    auto registryResults = RegistryParser::ParseAllRegistry();
    scanResults.push_back({"Registry", (int)registryResults.size(), 0, "Complete"});
    std::cout << "       Complete - " << registryResults.size() << " entries processed\n\n";

    // Run Process Scanner (separate from memory pattern scanning)
    std::cout << "[2/7] Process File Analysis...\n";
    auto processFileResults = ProcessScanner::ScanAllProcesses();
    ProcessScanner::ExportToCSV(processFileResults, "ProcessFiles.csv");
    scanResults.push_back({"ProcessFiles", (int)processFileResults.size(), 0, "Complete"});
    std::cout << "       Complete - " << processFileResults.size() << " file references found\n\n";

    // Run PCA Application Launch Parser
    std::cout << "[3/7] PCA Application Launch Analysis...\n";
    auto pcaResults = PcaAppLaunch::ParsePcaAppLaunch();
    scanResults.push_back({"PCA_AppLaunch", (int)pcaResults.size(), 0, "Complete"});
    std::cout << "       Complete - " << pcaResults.size() << " launch entries\n\n";

    // Run Prefetch Analyzer
    std::cout << "[4/7] Prefetch File Analysis...\n";
    PrefetchAnalyzer analyzer;
    std::string adminStatus = "Standard User";
    if (analyzer.CheckAdminPrivileges()) {
        adminStatus = "Administrator";
    }
    analyzer.AnalyzePrefetchFiles("C:\\Windows\\Prefetch");
    analyzer.LogToCSV("prefetch_analysis.csv");
    scanResults.push_back({"Prefetch", 0, 0, "Complete (" + adminStatus + ")"});
    std::cout << "       Complete - Prefetch analysis finished\n\n";

    // Run Service Checker
    std::cout << "[5/7] Service Analysis...\n";
    auto serviceResults = ServiceScanner::CheckServices();
    scanResults.push_back({"Services", (int)serviceResults.size(), 0, "Complete"});
    std::cout << "       Complete - Service scan finished\n\n";

    // Run Jump List Parser
    std::cout << "[6/7] Jump List Analysis...\n";
    auto jumpListResults = JumpListParser::ParseAllJumpLists();
    scanResults.push_back({"JumpLists", (int)jumpListResults.size(), 0, "Complete"});
    std::cout << "       Complete - " << jumpListResults.size() << " entries analyzed\n\n";

    // Run Direct Finds and Strings Scanner
    std::cout << "[7/8] Direct File System & Memory Pattern Scan...\n";
    auto directResults = DirectFinds::ScanDirectFinds();
    scanResults.push_back({"DirectFinds", (int)directResults.size(), 0, "Complete"});
    std::cout << "       Complete - " << directResults.size() << " findings\n\n";

    // Run Discord Downloads Scanner (Attachment-focused)
    std::cout << "[8/8] Discord Attachments Analysis...\n";
    auto discordDownloads = ExtractDiscordDownloads();
    CreateDiscordDownloadsCSV(discordDownloads);
    scanResults.push_back({"DiscordDownloads", (int)discordDownloads.size(), 0, "Complete"});
    std::cout << "       Complete - " << discordDownloads.size() << " Discord attachments found\n\n";

    // Final Summary
    std::cout << "===============================================\n";
    std::cout << "           SCAN COMPLETE - SUMMARY\n";
    std::cout << "===============================================\n\n";

    std::cout << "Scan Results:\n";
    for (const auto& result : scanResults) {
        std::cout << "• " << result.scanType << ": " << result.totalEntries << " entries\n";
    }

    std::cout << "\nOutput Files Generated:\n";
    std::cout << "• Registry.csv\n";
    std::cout << "• ProcessFiles.csv\n";
    std::cout << "• PcaAppLaunch.csv\n";
    std::cout << "• prefetch_analysis.csv\n";
    std::cout << "• Services.csv\n";
    std::cout << "• Jumplists.csv\n";
    std::cout << "• DirectFinds.csv\n";
    std::cout << "• DiscordAttachments.csv\n";

    std::cout << "\n\x1B[92m[SUCCESS]\x1B[0m Forensic scan completed successfully!\n";
    std::cout << "\x1B[94m[INFO]\x1B[0m All results saved locally to CSV files\n";
    std::cout << "\x1B[94m[INFO]\x1B[0m Problematic entries logged to console and detailed CSV files\n\n";

    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}