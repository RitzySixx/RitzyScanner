#ifndef DIRECTFINDS_H
#define DIRECTFINDS_H

#include <vector>
#include <string>

struct Finding {
    std::string type;
    std::string path;
    std::string details;
};

class DirectFinds {
public:
    static std::vector<Finding> ScanDirectFinds();
};

#endif