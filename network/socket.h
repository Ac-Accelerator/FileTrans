#pragma once
#include <netinet/in.h>
#include <sys/socket.h>
enum class ShutdownType { Read = SHUT_RD, Write = SHUT_WR, Both = SHUT_RDWR };
enum class SocketType {
  Stream = SOCK_STREAM,
  Datagram = SOCK_DGRAM,
  Raw = SOCK_RAW
};
enum class OptLevel { Socket = SOL_SOCKET, IP = IPPROTO_IP };

enum class SocketOpt {
  REUSEADDR = SO_REUSEADDR,       // reuse the address
  BROADCAST = SO_BROADCAST,       // broadcast
  REUSEPORT = SO_REUSEPORT,       // reuse the port
  RCVBUF = SO_RCVBUF,             // receive buffer
  SNDBUF = SO_SNDBUF,             // send buffer
  KEEPALIVE = SO_KEEPALIVE,       // keep alive
  BINDTODEVICE = SO_BINDTODEVICE, // bind to device
};

enum class IpOpt {
  PKTINFO = IP_PKTINFO,               // packet information
  TTL = IP_TTL,                       // time to live
  MULTICAST_TTL = IP_MULTICAST_TTL,   // multicast time to live
  MULTICAST_LOOP = IP_MULTICAST_LOOP, // multicast loop
};

enum class SocketDomain { IPv4 = AF_INET, IPv6 = AF_INET6 };

class Socket {
private:
  int _fd;

protected:
public:
  explicit Socket(int fd);
  Socket(int domain, int type, int protocol);
  Socket(SocketDomain domain, SocketType type, int protocol);

  // Copy constructor and assignment operator are deleted
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;

  Socket(Socket &&socket) noexcept;
  Socket &operator=(Socket &&socket) noexcept;

  ~Socket();

  void connect(const struct sockaddr *addr, socklen_t addrlen) const;

  void bind(const struct sockaddr *addr, socklen_t addrlen);

  Socket accept(struct sockaddr *addr, socklen_t *addrlen) const;

  int send(const void *buf, size_t len, int flags) const;

  int sendto(const void *buf, size_t len, int flags,
             const struct sockaddr *dest_addr, socklen_t addrlen) const;

  int sendmsg(const struct msghdr *msg, int flags) const;

  int recv(void *buf, size_t len, int flags) const;

  int recvfrom(void *buf, size_t len, int flags, struct sockaddr *src_addr,
               socklen_t *addrlen) const;

  int recvmsg(struct msghdr *msg, int flags) const;

  void listen(int backlog);

  void shutdown(int how) const;
  void shutdown(ShutdownType how) const;

  void setsockopt(int level, int optname, const void *optval,
                  socklen_t optlen) const;
  void setsockopt(OptLevel level, int optname, const void *optval,
                  socklen_t optlen) const;

  void setsockopt_socket(SocketOpt optname, const void *optval,
                         socklen_t optlen) const;

  void setsockopt_ip(IpOpt optname, const void *optval, socklen_t optlen) const;

  void getsockopt(int level, int optname, void *optval,
                  socklen_t *optlen) const;
  void getsockopt(OptLevel level, int optname, void *optval,
                  socklen_t *optlen) const;

  void getsockname(struct sockaddr *addr, socklen_t *addrlen) const;

  void unblock();

  void block();

  void close();

  int getFd();
};