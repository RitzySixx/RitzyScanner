// Utils.h
#ifndef UTILS_H
#define UTILS_H
#include <string>

inline std::string escape_csv(const std::string& s) {
    std::string res;
    bool needs_quotes = s.find_first_of(",\"\n") != std::string::npos;
    if (needs_quotes) {
        res = "\"";
        for (char c : s) {
            if (c == '"') res += "\"\"";
            else res += c;
        }
        res += "\"";
    }
    else {
        res = s;
    }
    return res;
}

#endif