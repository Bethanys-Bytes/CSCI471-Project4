#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <cstdint>
#include <algorithm>

#include "logging.h"
#include "router.h"

using namespace std;

// Helper functions

// Convert string IP to num (binary)
uint32_t ipToNum(const string &ipStr) {
    uint32_t b1, b2, b3, b4;
    char dot;
    stringstream ss(ipStr);
    ss >> b1 >> dot >> b2 >> dot >> b3 >> dot >> b4;
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

// Convert IP num to string
string numToIP(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." + to_string((ip >> 16) & 0xFF) + "." + to_string((ip >>  8) & 0xFF) + "." + to_string(ip & 0xFF);
}

// Apply a network mask to an IP
uint32_t applyMask(uint32_t ip, int maskLen) {
    if (maskLen == 0) {
        return 0;
    }
    uint32_t mask = (0xFFFFFFFF << (32 - maskLen));
    return ip & mask; // bitwise AND for IP and subnet mask
}

// Check routing table file for available interfaces
vector<InterfaceEntry> parseInterfaces(const string &path) {
    vector<InterfaceEntry> interfaces;
    ifstream file(path);

    if (!file) {
        DEBUG << "Could not open interface config file." << ENDL;
        exit(-1);
    }

    string line;
    regex re(R"(^\s*([A-Za-z0-9]+)\s+([0-9\.]+)\/([0-9]+)\s*$)");

    while (getline(file, line)) {
        // Skip lines without any data or with comments
        if (line.empty() || regex_match(line, regex(R"(^\s*#.*$)"))) {
            continue;
        }

        smatch match;
        if (regex_match(line, match, re)) {
            InterfaceEntry e;
            e.name = match[1];
            e.ip = ipToNum(match[2]);
            e.maskLen = stoi(match[3]);
            e.network = applyMask(e.ip, e.maskLen);
            interfaces.push_back(e);
        } else {
            DEBUG << "Bad entry in configuration file, skipping to next line." << ENDL;
        }
    }
    return interfaces;
}

// Check routing table for available routers
vector<RouteEntry> parseRoutes(const string &path) {
    vector<RouteEntry> routes;
    ifstream file(path);

    if (!file) {
        DEBUG << "Could not open route table file." << ENDL;;
        exit(-1);
    }

    string line;
    regex re(R"(^\s*([0-9\.]+)\/([0-9]+)\s+([0-9\.]+)\s*$)");

    while (getline(file, line)) {
        if (line.empty() || regex_match(line, regex(R"(^\s*#.*$)"))) {
            continue;
        }

        smatch match;
        if (regex_match(line, match, re)) {
            RouteEntry r;
            r.network = applyMask(ipToNum(match[1]), stoi(match[2]));
            r.maskLen = stoi(match[2]);
            r.nextHop = ipToNum(match[3]);
            routes.push_back(r);
        } else {
            DEBUG << "Bad entry in routing table file, skipping to next line." << ENDL;
        }
    }
    return routes;
}

// Returns a pointer to best matching route or nullptr
RouteEntry* findRoute(uint32_t dest, vector<RouteEntry> &routes) {
    RouteEntry* best = nullptr;
    int bestMask = -1;

    // Determine best route via longest matching prefix
    for (auto &r : routes) {
        if (applyMask(dest, r.maskLen) == r.network) {
            if (r.maskLen > bestMask) {
                bestMask = r.maskLen;
                best = &r;
            }
        }
    }
    return best;
}

// Determine which interface forwards to nextHop
InterfaceEntry* findOutgoingInterface(
    uint32_t nextHop,
    vector<InterfaceEntry> &ifs
) {
    for (auto &iface : ifs) {
        if (applyMask(nextHop, iface.maskLen) == iface.network) {
            return &iface;
        }
    }
    return nullptr;
}

void processPacket(uint32_t dest, vector<InterfaceEntry> &interfaces, vector<RouteEntry> &routes, ostream &out, int debugLevel) {
    // Check if destination is directly reachable
    for (auto &iface : interfaces) {
        if (applyMask(dest, iface.maskLen) == iface.network) {
            DEBUG << "Packet on same subnet as destination." << ENDL;
            out << "Packet now being sent to destination " << numToIP(dest) << ", leaving router from interface " << iface.name << std::endl;
            return;
        }
    }

    DEBUG << "Packet destination is not on same subnet, will be forwarded now." << ENDL;

    // Find longest prefix match in routing table
    RouteEntry *route = findRoute(dest, routes);

    if (!route) {
        // No route found means destination is unreachable
        out << numToIP(dest) << ": unreachable\n";
        return;
    }

    // Determine interface for next hop
    InterfaceEntry *iface = findOutgoingInterface(route->nextHop, interfaces);

    if (!iface) {
        // Should only occur with malformed input
        DEBUG << "Bad interface, can't find next hop." << ENDL;
        out << "Destination " << numToIP(dest) << " is unreachable." << std::endl;
        return;
    }

    // Print forwarding information
    out << "Packet destination is " << numToIP(dest) << ", leaving router from interface " << iface->name << " to next hop " << numToIP (route->nextHop) << std::endl;
}



int main(int argc, char *argv[]) {

    string configFile, routeFile, inputFile, outputFile;
    int debugLevel = 4;

    for (int i = 1; i < argc; i++) {
        string flag = argv[i];
        if (flag == "-h") {
            std::cout << "Usage: ./router -c <configFile> -r <routeTable> [-i <inputFile>] [-o <outputFile>] [-d <debugLevel>] [-h]\nDefault for input and output is stdin and stdout." << std::endl;
            return 0;
        }

        if (i + 1 < argc) {
            string arg = argv[i + 1];

            if (flag == "-c") {
                configFile = arg;
            } else if (flag == "-r") {
                routeFile = arg;
            } else if (flag == "-i") {
                inputFile = arg;
            } else if (flag == "-o") {
                outputFile = arg;
            } else if (flag == "-d") {
                debugLevel = stoi(arg);
            } else {
                std::cout << "Unknown flag received, or one or more flags are missing their arguments. Use -h to see valid options." << std::endl;
                return -1;
            }
        }

        i++; // Must double increment to get the next flag
    }

    // -c and -r are required flags
    if (configFile == "") {
        std::cout << "Missing configuration file! For more info, use the -h flag." << std::endl;
    } else if (routeFile == "") {
        std::cout << "Missing route table file! For more info, use the -h flag." << std::endl;
    } else {
        DEBUG << "Proper flags received." << ENDL;
    }

    // Load config files
    auto interfaces = parseInterfaces(configFile);
    auto routes = parseRoutes(routeFile);


    // Set up input to be stdin unless the -i flag was specified
    istream *in = &cin;
    ifstream fileIn;
    if (!inputFile.empty()) {
        fileIn.open(inputFile);
        if (!fileIn) {
            DEBUG << "Error: could not open input file." << ENDL;
            return -1;
        }
        in = &fileIn;
        DEBUG << "Now opening input file." << ENDL;
    } else {
        std::cout << "No input file specified. Ready to use stdin." << std::endl;
    }

    // Set up output to be stdout unless the -o flag was specified
    ostream *out = &cout;
    ofstream fileOut;
    if (!outputFile.empty()) {
        fileOut.open(outputFile);
        if (!fileOut) {
            DEBUG << "Error: could not open output file." << ENDL;
            return -1;
        }
        out = &fileOut;
        DEBUG << "Now opening output file." << ENDL;
    } else {
        std::cout << "No output file specified. Program will use stdout." << std::endl;
    }

    // Process packets per line from the input
    string line;
    while (getline(*in, line)) {
        // If line has no data, continue
        if (line.empty() || regex_match(line, regex(R"(^\s*#.*$)"))) {
            continue;
        }

        uint32_t dest = ipToNum(line);

        processPacket(dest, interfaces, routes, *out, debugLevel);
    }

    std::cout << "Packets done processing! Program will now exit." << std::endl;
    fileIn.close();
    fileOut.close();

    return 0;
}