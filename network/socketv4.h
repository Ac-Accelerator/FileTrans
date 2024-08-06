#pragma once
#include "common.h"
#include "socket.h"
#include <string>
class IPv4Socket : public Socket {
private:
public:
  IPv4Socket(Socket &&socket);

  IPv4Socket(SocketType type, int protocol);
  IPv4Socket(const IPv4Socket &) = delete;
  IPv4Socket &operator=(const IPv4Socket &) = delete;
  IPv4Socket(IPv4Socket &&socket) noexcept;
  IPv4Socket &operator=(IPv4Socket &&socket) noexcept;
  ~IPv4Socket();

  using Socket::connect;
  void connect(uint32_t ip, uint16_t port) const;
  void connect(const std::string &host, uint16_t port) const;

  using Socket::bind;
  void bind(uint32_t ip, uint16_t port);
  void bind(const std::string &host, uint16_t port);

  using Socket::accept;
  IPv4Socket accept(uint32_t &ip, uint16_t &port) const;
  IPv4Socket accept(std::string &host, uint16_t &port) const;
  IPv4Socket accept() const;

  using Socket::sendto;
  int sendto(const void *buf, size_t len, int flags, uint32_t ip,
             uint16_t port) const;
  int sendto(const void *buf, size_t len, int flags, const std::string &host,
             uint16_t port) const;

  using Socket::recvfrom;
  int recvfrom(void *buf, size_t len, int flags, uint32_t &ip,
               uint16_t &port) const;
  int recvfrom(void *buf, size_t len, int flags, std::string &host,
               uint16_t &port) const;
  int recvfrom(void *buf, size_t len, int flags) const;

  using Socket::getsockname;
  void getsockname(uint32_t &ip, uint16_t &port) const;
};

uint32_t resolveHost(const std::string &host);