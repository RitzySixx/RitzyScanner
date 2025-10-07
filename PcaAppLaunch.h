#pragma once
#include <string>
#include <vector>

namespace PcaAppLaunch {
    struct PcaEntry {
        std::string executionTime;
        std::string path;
        std::string signature;
        std::string trusted;
        std::string sha256;
        std::string fileSize;
        std::string creationTime;
        std::string accessTime;
        std::string writeTime;
        std::string name;
    };

    std::vector<PcaEntry> ParsePcaAppLaunch();
}