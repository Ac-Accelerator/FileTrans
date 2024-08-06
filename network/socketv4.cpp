#include "socketv4.h"
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <stdexcept>

IPv4Socket::IPv4Socket(SocketType type, int protocol)
    : Socket(SocketDomain::IPv4, type, protocol) {}

IPv4Socket::IPv4Socket(Socket &&fd) : Socket(std::move(fd)) {}

IPv4Socket::IPv4Socket(IPv4Socket &&socket) noexcept
    : Socket(std::move(socket)) {}

IPv4Socket &IPv4Socket::operator=(IPv4Socket &&socket) noexcept {
  Socket::operator=(std::move(socket));
  return *this;
}

IPv4Socket::~IPv4Socket() {}

void IPv4Socket::connect(uint32_t ip, uint16_t port) const {
  struct sockaddr_in addr={};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(ip);
  connect(reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
}

void IPv4Socket::connect(const std::string &host, uint16_t port) const {
  uint32_t ip = resolveHost(host);
  connect(ip, port);
}

void IPv4Socket::bind(uint32_t ip, uint16_t port) {
  struct sockaddr_in addr={};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(ip);
  Socket::bind(reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
}

void IPv4Socket::bind(const std::string &host, uint16_t port) {
  uint32_t ip = resolveHost(host);
  bind(ip, port);
}

IPv4Socket IPv4Socket::accept(uint32_t &ip, uint16_t &port) const {
  struct sockaddr_in addr = {};
  socklen_t addrlen;
  Socket newSocket =
      Socket::accept(reinterpret_cast<sockaddr *>(&addr), &addrlen);

  ip = ntohl(addr.sin_addr.s_addr);
  port = ntohs(addr.sin_port);
  return IPv4Socket(std::move(newSocket));
}

IPv4Socket IPv4Socket::accept(std::string &host, uint16_t &port) const {
  uint32_t ip;
  IPv4Socket newSocket = accept(ip, port);
  char ipStr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN);
  host = ipStr;
  return newSocket;
}

IPv4Socket IPv4Socket::accept() const {
  return Socket::accept(nullptr, nullptr);
}

int IPv4Socket::sendto(const void *buf, size_t len, int flags, uint32_t ip,
                       uint16_t port) const {
  struct sockaddr_in addr={};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(ip);
  return Socket::sendto(buf, len, flags,
                        reinterpret_cast<struct sockaddr *>(&addr),
                        sizeof(addr));
}

int IPv4Socket::sendto(const void *buf, size_t len, int flags,
                       const std::string &host, uint16_t port) const {
  uint32_t ip = resolveHost(host);
  return sendto(buf, len, flags, ip, port);
}

int IPv4Socket::recvfrom(void *buf, size_t len, int flags, uint32_t &ip,
                         uint16_t &port) const {
  struct sockaddr_in addr={};
  socklen_t addrlen = sizeof(addr);
  int ret = Socket::recvfrom(
      buf, len, flags, reinterpret_cast<struct sockaddr *>(&addr), &addrlen);
  ip = ntohl(addr.sin_addr.s_addr);
  port = ntohs(addr.sin_port);
  return ret;
}

int IPv4Socket::recvfrom(void *buf, size_t len, int flags, std::string &host,
                         uint16_t &port) const {
  uint32_t ip;
  int ret = recvfrom(buf, len, flags, ip, port);
  char ipStr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN);
  host = ipStr;
  return ret;
}

int IPv4Socket::recvfrom(void *buf, size_t len, int flags) const {
  return Socket::recvfrom(buf, len, flags, nullptr, nullptr);
}

void IPv4Socket::getsockname(uint32_t &ip, uint16_t &port) const {
  struct sockaddr_in addr={};
  socklen_t addrlen = sizeof(addr);
  Socket::getsockname(reinterpret_cast<struct sockaddr *>(&addr), &addrlen);
  ip = ntohl(addr.sin_addr.s_addr);
  port = ntohs(addr.sin_port);
}

uint32_t resolveHost(const std::string &host) {
  uint32_t ip;
  if (inet_pton(AF_INET, host.c_str(), &ip) !=
      1) { // convert string to network address
    // host is not a valid IP address, try to resolve it
    struct addrinfo hints, *res = nullptr, *p = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res)) {
      throw std::runtime_error("Failed to resolve host");
    }

    for (p = res; p != nullptr; p = p->ai_next) {
      if (p->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 =
            reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
        ip = ntohl(ipv4->sin_addr.s_addr);
        freeaddrinfo(res);
        return ip;
      }
    }
    freeaddrinfo(res);
    throw std::runtime_error("Failed to resolve host");
  }
  return ntohl(ip);
}