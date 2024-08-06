#include "stun.h"
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdexcept>
#include <unistd.h>
StunMessage::StunMessage(char *message, int size) {
  if (message == nullptr || size <= STUN_TRANSACTION_ID_LENGTH + 4 ||
      size > MAX_STUN_MESSAGE_SIZE ||
      ntohs(*reinterpret_cast<uint16_t *>(&message[2])) + 4 +
              STUN_TRANSACTION_ID_LENGTH !=
          size) {
    throw std::invalid_argument("invalid message");
  }
  memcpy(&_message[0], message, size);
  memcpy(&_transactionId[0], &_message[4], STUN_TRANSACTION_ID_LENGTH);
  _size = size;
}

void StunMessage::addHead(StunMessageType msgType, StunMessageClass msgClass) {
  uint16_t msgTypeField = 0;
  msgTypeField = (msgType & 0x0f80) << 2;
  msgTypeField |= (msgType & 0x0070) << 1;
  msgTypeField |= (msgType & 0x000f);
  msgTypeField |= (msgClass & 0x02) << 7;
  msgTypeField |= (msgClass & 0x01) << 4;
  *reinterpret_cast<uint16_t *>(&_message[0]) = htons(msgTypeField);
  *reinterpret_cast<uint16_t *>(&_message[2]) = 0;
  _size = 4;
}

void StunMessage::addTransactionId() {
  int randomfile = open("/dev/urandom", O_RDONLY);
  if (randomfile < 0) {
    throw std::runtime_error("open /dev/urandom");
  }

  int seed;
  if (read(randomfile, &seed, sizeof(seed)) == -1) {
    throw std::runtime_error("read /dev/urandom");
  }
  close(randomfile);

  seed ^= time(nullptr);
  seed ^= getpid();
  srand(seed);

  *reinterpret_cast<uint32_t *>(&_message[4]) = htonl(STUN_COOKIE);
  for (int i = 4; i < STUN_TRANSACTION_ID_LENGTH - 4; i++) {
    _message[i + 4] = rand() % 256;
  }
  for (int i = 12; i < STUN_TRANSACTION_ID_LENGTH; i++) {
    _message[i + 4] = 0;
  }
  memcpy(&_transactionId[0], &_message[4], STUN_TRANSACTION_ID_LENGTH);
}

void StunMessage::addAttr(uint16_t attrType, const char *attrValue,
                          uint16_t attrLength) {
  size_t pos = std::max(_size, 4 + STUN_TRANSACTION_ID_LENGTH);
  if (pos + 4 + attrLength > MAX_STUN_MESSAGE_SIZE) {
    throw std::runtime_error("message is too long");
  }

  *reinterpret_cast<uint16_t *>(&_message[pos]) = htons(attrType);
  *reinterpret_cast<uint16_t *>(&_message[pos + 2]) = htons(attrLength);
  pos += 4;

  if (attrValue == nullptr) {
    attrLength = 0;
  }
  uint8_t zeroPadding[4] = {0};
  int paddingLength = (attrLength % 4) ? (4 - (attrLength % 4)) : 0;

  if (attrLength > 0) {
    memcpy(&_message[pos], attrValue, attrLength);
    pos += attrLength;
  }
  if (paddingLength > 0) {
    memcpy(&_message[pos], zeroPadding, paddingLength);
    pos += paddingLength;
  }
  *reinterpret_cast<uint16_t *>(&_message[2]) =
      htons(pos - STUN_TRANSACTION_ID_LENGTH - 4);
  _size = pos;
}

int StunMessage::findAttr(uint16_t attrType, uint16_t &attrLength) const {
  uint16_t pos = 20;
  while (pos < _size) {
    uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(&_message[pos]));
    uint16_t length =
        ntohs(*reinterpret_cast<const uint16_t *>(&_message[pos + 2]));
    if (type == attrType) {
      attrLength = length;
      return pos + 4;
    }
    pos += 4 + length;
  }
  return 0;
}

const char *const StunMessage::getMessage() const { return _message.data(); }

const char *const StunMessage::getTransactionId() const {
  return _transactionId.data();
}

void StunMessage::send(const IPv4Socket &socket, uint32_t ip, uint16_t port) {
  socket.sendto(_message.data(), _size, 0, ip, port);
}

void StunMessage::send(const IPv4Socket &socket, std::string ip,
                       uint16_t port) {
  socket.sendto(_message.data(), _size, 0, ip, port);
}

int getMappedAddress(const StunMessage &message, uint32_t &ip, uint16_t &port) {
  // validate
  auto messageData = message.getMessage();
  uint16_t msgType = ntohs(*reinterpret_cast<const uint16_t *>(messageData));
  uint16_t msgLength =
      ntohs(*reinterpret_cast<const uint16_t *>(messageData + 2));
  if (msgType != 0x0101 ||
      msgLength != message.getSize() - (4 + STUN_TRANSACTION_ID_LENGTH)) {
    return -1;
  }

  int pos;
  uint16_t attrLength;
  int pos_xor;

  pos = message.findAttr(STUN_ATTRIBUTE_MAPPEDADDRESS, attrLength);
  if ((pos_xor =
           message.findAttr(STUN_ATTRIBUTE_XORMAPPEDADDRESS, attrLength))) {
    pos = pos_xor;
  }

  port = *reinterpret_cast<const uint16_t *>(messageData + pos + 2);
  ip = *reinterpret_cast<const uint32_t *>(messageData + pos + 4);
  uint8_t *portP = reinterpret_cast<uint8_t *>(&port);
  uint8_t *ipP = reinterpret_cast<uint8_t *>(&ip);

  const uint8_t *transactionId =
      reinterpret_cast<const uint8_t *>(message.getTransactionId());
  if (pos_xor) {
    for (int i = 0; i < 2; i++)
      portP[i] ^= (transactionId[i]);
    for (int i = 0; i < 4; i++)
      ipP[i] ^= (transactionId[i]);
  }

  ip = ntohl(ip);
  port = ntohs(port);

  return 0;
}

void addChangeRequest(StunMessage &message, bool changeIP, bool changePort) {

  uint32_t changeRequest = 0;
  if (changeIP)
    changeRequest |= 0x04;
  if (changePort)
    changeRequest |= 0x02;
  changeRequest = htonl(changeRequest);
  message.addAttr(0x0003, reinterpret_cast<char *>(&changeRequest), 4);
  return;
}

int initRequestMessage(StunMessage &message) {
  message.addHead(StunMsgTypeBinding, StunMsgClassRequest);
  message.addTransactionId();
  return 0;
}

void getHeader(const StunMessage &message, uint16_t &msgType,
               uint16_t &msgLength) {
  auto messageData = message.getMessage();
  msgType = ntohs(*reinterpret_cast<const uint16_t *>(messageData));
  msgLength = ntohs(*reinterpret_cast<const uint16_t *>(messageData + 2));
}

void getOtherAddress(const StunMessage &message, uint32_t &ip, uint16_t &port) {
  auto messageData = message.getMessage();
  int pos;
  uint16_t attrLength;
  int pos_xor;

  pos = message.findAttr(STUN_ATTRIBUTE_OTHER_ADDRESS, attrLength);
  if (pos == 0) {
    pos = message.findAttr(STUN_ATTRIBUTE_CHANGEDADDRESS, attrLength);
  }
  port = *reinterpret_cast<const uint16_t *>(messageData + pos + 2);
  ip = *reinterpret_cast<const uint32_t *>(messageData + pos + 4);
  ip = ntohl(ip);
  port = ntohs(port);
}
bool sameTransactionId(const StunMessage &message1,
                       const StunMessage &message2) {
  return memcmp(message1.getTransactionId(), message2.getTransactionId(),
                STUN_TRANSACTION_ID_LENGTH) == 0;
}