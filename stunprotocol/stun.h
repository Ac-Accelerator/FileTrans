#pragma once
#include "socketv4.h"
#include <array>
#include <cstdint>
enum StunMessageType {
  StunMsgTypeBinding = 0x0001,
  StunMsgTypeInvalid = 0xffff
};
enum StunMessageClass {
  StunMsgClassRequest = 0x00,
  StunMsgClassIndication = 0x01,
  StunMsgClassSuccessResponse = 0x02,
  StunMsgClassFailureResponse = 0x03,
  StunMsgClassInvalidMessageClass = 0xff
};

enum NATStatus {
  Unknown = 0,
  NoNAT = 1,
  FullCone = 2,
  RestrictedCone = 3,
  PortRestrictedCone = 4,
  Symmetric = 5,
  SymmetricUDPFirewall = 6,
  UDPBlocked = 7,
};

const uint16_t STUN_ATTRIBUTE_MAPPEDADDRESS = 0x0001;
const uint16_t STUN_ATTRIBUTE_RESPONSEADDRESS = 0x0002;
const uint16_t STUN_ATTRIBUTE_CHANGEREQUEST = 0x0003;
const uint16_t STUN_ATTRIBUTE_SOURCEADDRESS = 0x0004;
const uint16_t STUN_ATTRIBUTE_CHANGEDADDRESS = 0x0005;
const uint16_t STUN_ATTRIBUTE_XORMAPPEDADDRESS = 0x0020;
const uint16_t STUN_ATTRIBUTE_OTHER_ADDRESS = 0x802c;

const int MAX_STUN_MESSAGE_SIZE = 800;
const uint32_t STUN_COOKIE = 0x2112A442;
const uint16_t STUN_TRANSACTION_ID_LENGTH = 16;

class StunMessage {
private:
  std::array<char, MAX_STUN_MESSAGE_SIZE> _message;
  std::array<char, STUN_TRANSACTION_ID_LENGTH> _transactionId;
  int _size;

public:
  StunMessage() = default;
  StunMessage(char *message, int size);
  void addHead(StunMessageType msgType, StunMessageClass msgClass);
  void addTransactionId();
  void addAttr(uint16_t attrType, const char *attrValue, uint16_t attrLength);
  int findAttr(uint16_t attrType, uint16_t &attrLength) const;
  void getMappedAddress(uint32_t &ip, uint16_t &port);

  const char *const getMessage() const;
  const char *const getTransactionId() const;
  const int getSize() const { return _size; };

  void send(const IPv4Socket &socket, uint32_t ip, uint16_t port);
  void send(const IPv4Socket &socket, std::string ip, uint16_t port);
};

int initRequestMessage(StunMessage &message);
void addChangeRequest(StunMessage &message, bool changeIP, bool changePort);
int getMappedAddress(const StunMessage &message, uint32_t &ip, uint16_t &port);
void getHeader(const StunMessage &message, uint16_t &msgType,
               uint16_t &msgLength);
void getOtherAddress(const StunMessage &message, uint32_t &ip, uint16_t &port);
bool sameTransactionId(const StunMessage &message1,
                       const StunMessage &message2);