#ifndef ROUTER_H
#define ROUTER_H

#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include "logging.h"

struct InterfaceEntry {
    std::string name;
    uint32_t ip;
    int maskLen;
    uint32_t network;
};

struct RouteEntry {
    uint32_t network;
    int maskLen;
    uint32_t nextHop;
};

uint32_t ipToUint32(const std::string &ipStr);

std::string uint32ToIP(uint32_t ip);

uint32_t applyMask(uint32_t ip, int maskLen);

std::vector<InterfaceEntry> parseInterfaces(const std::string &path);

std::vector<RouteEntry> parseRoutes(const std::string &path);

RouteEntry* findRoute(uint32_t dest, std::vector<RouteEntry> &routes);

InterfaceEntry* findOutgoingInterface(uint32_t nextHop, std::vector<InterfaceEntry> &interfaces);

void processPacket(uint32_t dest, std::vector<InterfaceEntry> &interfaces, std::vector<RouteEntry> &routes, std::ostream &out, int debugLevel);




#endif
