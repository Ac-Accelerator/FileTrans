#include "ft.h"
#include "socketevent.h"
#include "stunclient.h"
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

int main(int argc, char *argv[]) {

  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::cout << "sending? [Y/n] :";
  char c;
  std::cin >> c;
  bool sending = (c == 'Y' || c == 'y');

  uint32_t ip;
  uint16_t port;
  IPv4Socket UDPsocket(SocketType::Datagram, 0);
  int fd = UDPsocket.getFd();
  NATStatus status;
  std::thread detectNATStatus([&] {
    status = stunClient(fd, "stun.internetcalls.com", 3478, ip, port);
    UDPsocket = IPv4Socket(std::move(Socket(fd)));
  });

  // event base
  FtProtocol ft;
  IPv4Socket socket(SocketType::Stream, 0);
  socket.connect("127.0.0.1", 25566);

  char msg[4096];
  int len = 0;
  ft.getRegisterRequest(msg, len);
  socket.send(msg, len, 0);
  len = socket.recv(msg, 4096, 0);

  ft.processMessage(msg, len);
  uint16_t sessionID = ft.getSessionID();
  std::cout << "YOUR SESSION ID: " << sessionID << std::endl;

  detectNATStatus.join();
  if (status != NATStatus::Unknown && status != NATStatus::UDPBlocked) {

    char ipStr[16];
    ip = htonl(ip);
    inet_ntop(AF_INET, &ip, ipStr, 16);
    printf("IP: %s, Port: %d\n", ipStr, port);
  } else {
    std::cout << "NAT DETECTION FAILED" << std::endl;
  }

  FtProtocol::NS this_ns;
  this_ns._IP = ntohl(ip);
  this_ns._Port = port;
  this_ns._NatStatus = status;

  len = 0;
  ft.getNetStatusRequest(msg, len, &this_ns);
  socket.send(msg, len, 0);

  std::cout << "INPUT SESSION ID: ";

  std::cin >> sessionID;

  len = 0;
  ft.getSessionIDRequest(msg, len, sessionID);
  socket.send(msg, len, 0);
  len = socket.recv(msg, 4096, 0);
  ft.processMessage(msg, len);
  FtProtocol::NS other_ns = ft.getNetStatus();

  if (other_ns._NatStatus == NATStatus::Unknown ||
      other_ns._NatStatus == NATStatus::UDPBlocked ||
      other_ns._NatStatus == NATStatus::PortRestrictedCone) {
    std::cout << "USE TCP" << std::endl;
    if (sending) {
      ft.getDataRequest(msg, len);
      socket.send(msg, len, 0);

      // read from stdin
      int fd = open(argv[1], O_RDONLY);
      if (fd < 0) {
        std::cerr << "open failed" << std::endl;
        return 1;
      }
      while ((len = read(fd, msg, 4096)) > 0) {
        socket.send(msg, len, 0);
      }
      close(fd);

    } else {
      int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd < 0) {
        std::cerr << "open failed" << std::endl;
        return 1;
      }
      while ((len = socket.recv(msg, 4096, 0)) > 0) {
        write(fd, msg, len);
      }
    }
  } else {
  }

  return 0;
}