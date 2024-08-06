#include "stunclient.h"
#include "socketv4.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/epoll.h>
#include <unistd.h>

bool TransactionBindTest(int socket_fd, uint32_t ServerIP, uint16_t ServerPort,
                         bool changeIP, bool changePort) {
  static int epoll_fd = epoll_create(1);
  StunMessage stunMessage;
  initRequestMessage(stunMessage);
  addChangeRequest(stunMessage, changeIP, changePort);
  struct epoll_event event;
  event.events = EPOLLIN;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
    throw std::runtime_error("epoll_ctl failed");
  }
  IPv4Socket socket((Socket(socket_fd)));
  socket.unblock();
  struct epoll_event events[1];
  int recvSize = 0;
  char message[MAX_STUN_MESSAGE_SIZE];
  for (int i = 0; i < 3; i++) {
    stunMessage.send(socket, ServerIP, ServerPort);
    int num_events = epoll_wait(epoll_fd, events, 1, 500);
    if (num_events != 0) {
      recvSize = socket.recv(message, MAX_STUN_MESSAGE_SIZE, 0);
      try {
        StunMessage responseMessage(message, recvSize);
        if (sameTransactionId(stunMessage, responseMessage)) {
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket_fd, &event);
          socket.getFd();
          return true;
        }
      } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket_fd, &event);
        socket.getFd();
        return false;
      }
    }
    std::cout << "timeout" << i << std::endl;
  }
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket_fd, &event);
  socket.getFd();
  return false;
}

NATStatus stunClient(int socket_fd, std::string serverHost, uint16_t serverPort,
                     uint32_t &ip, uint16_t &port) {
  // 1. Create a socket
  IPv4Socket socket((Socket(socket_fd)));

  socket.bind((uint32_t)0, 0);
  socket.unblock();

  // 2. Create epoll
  int epoll_fd = epoll_create(1);
  if (epoll_fd == -1) {
    throw std::runtime_error("Failed to create epoll");
  }

  // 3. Add socket to epoll
  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.fd = socket_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
    throw std::runtime_error("epoll_ctl failed");
  }
  struct epoll_event events[1];

  // 4. Enable IP_PKTINFO
  int enable = 1;
  socket.setsockopt_ip(IpOpt::PKTINFO, &enable, sizeof(enable));

  // Prepare STUN message
  StunMessage stunMessage;
  initRequestMessage(stunMessage);
  addChangeRequest(stunMessage, false, false);

  int recvSize = 0;
  struct msghdr msg = {};
  struct iovec iov[1];
  struct cmsghdr *cmsg;
  struct in_pktinfo *pktinfo;

  char ipstr[INET_ADDRSTRLEN];
  char message[MAX_STUN_MESSAGE_SIZE];

  iov[0].iov_base = message;
  iov[0].iov_len = MAX_STUN_MESSAGE_SIZE;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  struct sockaddr_in server_addr;
  msg.msg_name = &server_addr;
  msg.msg_namelen = sizeof(server_addr);

  char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  // Send STUN message to server
  for (int i = 0; i < 3; i++) {
    stunMessage.send(socket, serverHost, serverPort);
    int num_events = epoll_wait(epoll_fd, events, 1, 500);
    if (num_events != 0) {
      recvSize = socket.recvmsg(&msg, 0);
      break;
    }
    std::cout << "timeout" << i << std::endl;
  }

  if (!recvSize) {
    std::cout << "No response from STUN server" << std::endl;
    socket.getFd();
    return UDPBlocked;
  }

  uint32_t localIP;
  uint16_t localPort;
  // Get local/remote IP and port
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
      pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
      socket.getsockname(localIP, localPort);
      localIP = htonl(pktinfo->ipi_addr.s_addr);
      inet_ntop(AF_INET, &pktinfo->ipi_addr, ipstr, sizeof(ipstr));
      printf("locat IP: %s:%d\n", ipstr, localPort);
      break;
    }
  }
  uint32_t serverIP = ntohl(server_addr.sin_addr.s_addr);

  // pharse response message , get mapped address
  StunMessage responseMessage(message, recvSize);
  if (getMappedAddress(responseMessage, ip, port) < 0) {
    socket.getFd();
    return Unknown;
  }

  if (localIP == ip) {
    std::cout << "No NAT\n";
    socket.getFd();
    return NoNAT;
  }

  std::cout << "After NAT\n"
            << "is Full Cone NAT?" << std::endl;

  // Check if it is Full Cone NAT///////////////////////////////////////////
  if (TransactionBindTest(socket_fd, serverIP, serverPort, true, true)) {
    std::cout << "NAT type: Full Cone NAT" << std::endl;
    socket.getFd();
    return FullCone;
  }

  // Check if it is Symmetric NAT///////////////////////////////////////////
  std::cout << "is Symetric NAT?" << std::endl;
  uint32_t otherIP;
  uint16_t otherPort;
  getOtherAddress(responseMessage, otherIP, otherPort);

  initRequestMessage(stunMessage);
  addChangeRequest(stunMessage, false, false);
  stunMessage.send(socket, otherIP, otherPort);

  recvSize = 0;
  for (int i = 0; i < 3; i++) {
    stunMessage.send(socket, serverHost, serverPort);
    int num_events = epoll_wait(epoll_fd, events, 1, 500);
    if (num_events != 0) {
      recvSize = socket.recvmsg(&msg, 0);
      uint32_t Ip2;
      uint16_t Port2;
      try {
        StunMessage responseMessage2(message, recvSize);
        if (sameTransactionId(responseMessage2, stunMessage)) {
          if (getMappedAddress(responseMessage2, Ip2, Port2) < 0) {
            socket.getFd();
            return Unknown;
          }
          if (Ip2 != ip) {
            std::cout << "NAT type: Symetric NAT" << std::endl;
            socket.getFd();
            return Symmetric;
          } else {
            break;
          }
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        socket.getFd();
        return Unknown;
      }
    }
    std::cout << "timeout" << i << std::endl;
  }

  std::cout << "is Restricted Cone NAT ?" << std::endl;

  // Check if it is Restricted Cone
  // NAT///////////////////////////////////////////
  if (TransactionBindTest(socket_fd, serverIP, serverPort, false, true)) {
    std::cout << "NAT type: Restricted Cone NAT" << std::endl;
    socket.getFd();
    return RestrictedCone;
  } else {
    std::cout << "NAT type: Port Restricted Cone NAT" << std::endl;
    socket.getFd();
    return PortRestrictedCone;
  }
}