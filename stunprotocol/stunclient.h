#pragma once
#include "stun.h"
#include <cstdint>
#include <string>

NATStatus stunClient(int socket_fd, std::string serverHost, uint16_t serverPort,
                     uint32_t &ip, uint16_t &port);