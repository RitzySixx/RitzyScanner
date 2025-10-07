#pragma once
#include <string>
#include <vector>

namespace DirectFinds {
    struct YaraRule {
        std::string name;
        std::vector<std::string> x_strings_ascii;
        std::vector<std::wstring> x_strings_wide;
        std::vector<std::string> s_strings_ascii;
        std::vector<std::wstring> s_strings_wide;
        uint64_t maxFileSize;
        int minXMatches;
        int minTotalMatches;
        bool allStrings;
    };

    struct Finding {
        std::string reason;
        std::string path;
        std::string details;
        uintmax_t fileSize;
        std::string sha256;
        std::string signature;
        std::string trusted;
        std::string creationTime;
        std::string accessTime;
        std::string writeTime;
        std::string name;
        std::string locationFound; // Added field

        Finding(std::string r, std::string p, std::string d, uintmax_t fs, std::string s256, std::string sig, std::string tr, std::string ct, std::string at, std::string wt, std::string n, std::string lf) :
            reason(r), path(p), details(d), fileSize(fs), sha256(s256), signature(sig), trusted(tr), creationTime(ct), accessTime(at), writeTime(wt), name(n), locationFound(lf) {}
    };

    std::vector<Finding> ScanDirectFinds();
}