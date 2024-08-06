#include "socket.h"
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
Socket::Socket(int domain, int type, int protocol) {
  _fd = socket(domain, type, protocol);
  if (_fd == -1) {
    throw std::runtime_error("Failed to create socket");
  }
}

Socket::Socket(SocketDomain domain, SocketType type, int protocol)
    : Socket(static_cast<int>(domain), static_cast<int>(type), protocol) {}

Socket::Socket(int fd) : _fd(fd) {}

Socket::Socket(Socket &&socket) noexcept : _fd(socket._fd) { socket._fd = -1; }

Socket &Socket::operator=(Socket &&socket) noexcept {
  if (this != &socket) {
    if (_fd != -1) {
      try {
        close();
      } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::abort();
      }
    }
    _fd = socket._fd;
    socket._fd = -1;
  }
  return *this;
}

Socket::~Socket() {
  if (_fd != -1) {
    try {
      close();
    } catch (const std::exception &e) {
      std::cerr << e.what() << std::endl;
      std::abort();
    }
  }
}

void Socket::close() { // throw exception ,always return 0
  if (_fd == -1) {
    return;
  }
  if (::close(_fd) == -1) {
    throw std::runtime_error("Failed to close socket");
  }
  _fd = -1;
  return;
}

void Socket::connect(const struct sockaddr *addr, socklen_t addrlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to connect, socket not created");
  }
  if (::connect(_fd, addr, addrlen) == -1) {
    throw std::runtime_error("Failed to connect");
  }
  return;
}

void Socket::bind(const struct sockaddr *addr, socklen_t addrlen) {
  if (_fd == -1) {
    throw std::runtime_error("Failed to bind, socket not created");
  }
  if (::bind(_fd, addr, addrlen) == -1) {
    throw std::runtime_error("Failed to bind");
  }
  return;
}

Socket Socket::accept(struct sockaddr *addr, socklen_t *addrlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to accept, socket not created");
  }
  int new_fd = ::accept(_fd, addr, addrlen);
  if (new_fd == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to accept");
  }
  return Socket(new_fd);
}

int Socket::send(const void *buf, size_t len, int flags) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to send, socket not created");
  }
  ssize_t ret = ::send(_fd, buf, len, flags);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to send");
  }
  return ret;
}

int Socket::sendto(const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to sendto, socket not created");
  }
  ssize_t ret = ::sendto(_fd, buf, len, flags, dest_addr, addrlen);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to sendto");
  }
  return ret;
}

int Socket::sendmsg(const struct msghdr *msg, int flags) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to sendmsg, socket not created");
  }
  ssize_t ret = ::sendmsg(_fd, msg, flags);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to sendmsg");
  }
  return ret;
}

int Socket::recv(void *buf, size_t len, int flags) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to recv, socket not created");
  }
  ssize_t ret = ::recv(_fd, buf, len, flags);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to recv");
  }
  return ret;
}

int Socket::recvfrom(void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to recvfrom, socket not created");
  }
  ssize_t ret = ::recvfrom(_fd, buf, len, flags, src_addr, addrlen);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to recvfrom");
  }
  return ret;
}

int Socket::recvmsg(struct msghdr *msg, int flags) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to recvmsg, socket not created");
  }
  ssize_t ret = ::recvmsg(_fd, msg, flags);
  if (ret == -1 && errno != EAGAIN) {
    throw std::runtime_error("Failed to recvmsg");
  }
  return ret;
}

// int

void Socket::listen(int backlog) {
  if (_fd == -1)
    throw std::runtime_error("Failed to listen, socket not created");
  if (::listen(_fd, backlog) == -1) {
    throw std::runtime_error("Failed to listen");
  }
  return;
}

void Socket::shutdown(int how) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to shutdown, socket not created");
  }
  if (::shutdown(_fd, how) == -1) {
    throw std::runtime_error("Failed to shutdown");
  }
  return;
}

void Socket::shutdown(ShutdownType how) const {
  shutdown(static_cast<int>(how));
}

void Socket::setsockopt(int level, int optname, const void *optval,
                        socklen_t optlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to setsockopt, socket not created");
  }
  if (::setsockopt(_fd, level, optname, optval, optlen) == -1) {
    throw std::runtime_error("Failed to setsockopt");
  }
  return;
}

void Socket::setsockopt(OptLevel level, int optname, const void *optval,
                        socklen_t optlen) const {
  setsockopt(static_cast<int>(level), optname, optval, optlen);
}

void Socket::setsockopt_socket(SocketOpt optname, const void *optval,
                               socklen_t optlen) const {
  setsockopt(SOL_SOCKET, static_cast<int>(optname), optval, optlen);
}

void Socket::setsockopt_ip(IpOpt optname, const void *optval,
                           socklen_t optlen) const {
  setsockopt(IPPROTO_IP, static_cast<int>(optname), optval, optlen);
}

void Socket::getsockopt(int level, int optname, void *optval,
                        socklen_t *optlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to getsockopt, socket not created");
  }
  if (::getsockopt(_fd, level, optname, optval, optlen) == -1) {
    throw std::runtime_error("Failed to getsockopt");
  }
  return;
}

void Socket::getsockopt(OptLevel level, int optname, void *optval,
                        socklen_t *optlen) const {
  getsockopt(static_cast<int>(level), optname, optval, optlen);
}

void Socket::getsockname(struct sockaddr *addr, socklen_t *addrlen) const {
  if (_fd == -1) {
    throw std::runtime_error("Failed to getsockname, socket not created");
  }
  if (::getsockname(_fd, addr, addrlen) == -1) {
    throw std::runtime_error("Failed to getsockname");
  }
  return;
}

int Socket::getFd() {
  int ret = _fd;
  _fd = -1;
  return ret;
}

void Socket::unblock() {
  if (_fd == -1) {
    throw std::runtime_error("Failed to unblock, socket not created");
  }
  int flags = fcntl(_fd, F_GETFL, 0);
  if (fcntl(_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    throw std::runtime_error("Failed to unblock");
  }
  return;
}

void Socket::block() {
  if (_fd == -1) {
    throw std::runtime_error("Failed to block, socket not created");
  }
  int flags = fcntl(_fd, F_GETFL, 0);
  if (fcntl(_fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
    throw std::runtime_error("Failed to block");
  }
  return;
}