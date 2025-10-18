#pragma once
#include <string>
#include <vector>
#include <windows.h>

// Structure to hold Discord download information
struct DiscordDownload {
    std::string fullUrl;
    std::string fileName;
    std::string processName;
    DWORD processId;
    std::string timestamp;
};

// Function declarations for Discord downloads scanner
std::vector<std::string> ExtractDiscordURLs(const std::string& content);
std::vector<DiscordDownload> ExtractDiscordDownloads();
std::vector<DiscordDownload> ExtractDiscordDownloadsEnhanced();
void CreateDiscordDownloadsCSV(const std::vector<DiscordDownload>& downloads);