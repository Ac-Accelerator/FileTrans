#include "hiredis.h"
#include "stun.h"
#include <cstdint>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <mutex>
#include <queue>
enum FtMessageClass {
  FT_MSG_CLASS_REQUEST = 0,
  FT_MSG_CLASS_RESPONSE = 1,
  FT_MSG_CLASS_NOTIFICATION = 2,
  FT_MSG_CLASS_ERROR = 3,
};

enum FtMessageType {
  FT_MSG_TYPE_REGISTER = 0,
  FT_MSG_TYPE_SESSIONID = 1,
  FT_MSG_TYPE_NETSTATUS = 2,
  FT_MSG_TYPE_DATA = 3,
};

class FtProtocol {
public:
  struct NS {
    NATStatus _NatStatus = Unknown;
    uint32_t _IP = 0;
    uint16_t _Port = 0;
  };

private:
  bool _Registed = false;
  bool _transmitting = false;

  uint16_t _SessionID = UINT16_MAX;
  uint16_t _targetSessionID = UINT16_MAX;
  struct NS _Ns;
  redisContext *_redis = nullptr;
  bufferevent *_bev = nullptr;
  bufferevent *_targetBev = nullptr;

  void HandleSessionIDRequest(char *msg, int &len); // server
  void HandleRegisterRequest(char *msg, int &len);  // server
  void HandleSessionID(const char *msg, int len);   // client
  void HandleNetStatus(const char *msg, int len);   // client

  void getSessionIDResponse(char *msg, int &len);               // server
  void getNetStatusResponse(char *msg, int &len, const NS *Ns); // server
  void setNetStatus(const char *msg, int len);                  // server
  void HandleData(const char *msg, int len);                    // server

public:
  void getRegisterRequest(char *msg, int &len);                      // client
  void getSessionIDRequest(char *msg, int &len, uint16_t sessionID); // client
  void getNetStatusRequest(char *msg, int &len, const NS *Ns);       // client
  void getDataRequest(char *msg, int &len);                          // client
  bufferevent *getTargetBev() { return _targetBev; }

  FtProtocol() = default;
  FtProtocol(redisContext *redis, bufferevent *bev)
      : _redis(redis), _bev(bev){};
  FtProtocol(const FtProtocol &) = delete;
  FtProtocol &operator=(const FtProtocol &) = delete;
  ~FtProtocol() {
    if (_redis) {
      redisReply *reply;
      reply = (redisReply *)redisCommand(_redis, "DEL %d", _SessionID);
      freeReplyObject(reply);
      reply = (redisReply *)redisCommand(_redis, "DEL BEV%d", _SessionID);
      freeReplyObject(reply);
    }
  }
  int processMessage(char *msg, int &len);
  uint16_t getSessionID() const { return _SessionID; }
  NS getNetStatus() const { return _Ns; }
  friend void Transmit(bufferevent *bev, void *ctx);
};

struct TransferContext {
  bufferevent *targetBev;
  char *data;
  int len;
};