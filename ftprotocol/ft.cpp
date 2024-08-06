#include "ft.h"
#include <cstring>
#include <event2/buffer.h>
#include <event2/event.h>
#include <iostream>
#include <mutex>
#include <random>
#include <stdexcept>
#include <unistd.h>

int FtProtocol::processMessage(char *msg, int &len) {
  // validate message
  if (len < 4)
    return 1;

  uint8_t msg_class = msg[0];
  uint8_t msg_type = msg[1];

  uint16_t msg_len = *reinterpret_cast<const uint16_t *>(msg + 2);

  if (len != msg_len + 4)
    return 1;

  switch (msg_class) {
  case FT_MSG_CLASS_REQUEST:
    switch (msg_type) {
    case FT_MSG_TYPE_REGISTER:
      // server receive register request,return sessionID
      HandleRegisterRequest(msg, len);
      break;
    case FT_MSG_TYPE_SESSIONID:
      // client receive sessionID,return net status
      HandleSessionIDRequest(msg, len);
      break;
    case FT_MSG_TYPE_DATA:
      HandleData(msg, len);
      len = 0;
      break;
    case FT_MSG_TYPE_NETSTATUS:
      setNetStatus(msg, len);
      len = 0;
      break;
    default:
      return 1;
    }
    break;
  case FT_MSG_CLASS_RESPONSE:
    switch (msg_type) {
    case FT_MSG_TYPE_SESSIONID:
      // client receive SessionID, handle it
      HandleSessionID(msg, len);
      len = 0;
      break;
    case FT_MSG_TYPE_NETSTATUS:
      // client receive net status
      HandleNetStatus(msg, len);
      len = 0;
      break;
    case FT_MSG_TYPE_DATA:
      // processData(msg, len);
      break;
    default:
      return 1;
    }
    break;
  case FT_MSG_CLASS_NOTIFICATION:
    switch (msg_type) {
    case FT_MSG_TYPE_NETSTATUS:
      // server receive net status
      HandleNetStatus(msg, len);
      len = 0;
      break;
    case FT_MSG_TYPE_DATA:
      // processData(msg, len);
      break;
    default:
      return 1;
    }
    break;
  default:
    return 1;
  }
  return 0;
}

void FtProtocol::getRegisterRequest(char *msg, int &len) {
  msg[0] = FT_MSG_CLASS_REQUEST;
  msg[1] = FT_MSG_TYPE_REGISTER;
  *reinterpret_cast<uint16_t *>(msg + 2) = 0;
  len = 4;
}

void FtProtocol::getSessionIDResponse(char *msg, int &len) {
  msg[0] = FT_MSG_CLASS_RESPONSE;
  msg[1] = FT_MSG_TYPE_SESSIONID;
  *reinterpret_cast<uint16_t *>(msg + 2) = 2;
  *reinterpret_cast<uint16_t *>(msg + 4) = _SessionID;
  len = 6;
}

void FtProtocol::HandleRegisterRequest(char *msg, int &len) {
  if (_Registed || _transmitting) {
    len = 0;
    return;
  }

  // random sessionID
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<uint16_t> dis(1, 65534);

  redisReply *reply;
  do {
    _SessionID = dis(gen);
    reply = (redisReply *)redisCommand(_redis, "EXISTS %d", _SessionID);
    if (reply->type != REDIS_REPLY_INTEGER) {
      freeReplyObject(reply);
      throw std::runtime_error("redisCommand EXISTS failed");
    }
  } while (reply->integer != 0);
  freeReplyObject(reply);
  reply = (redisReply *)redisCommand(_redis, "SET %d %b", _SessionID, &_Ns,
                                     sizeof(NS));

  if (reply->type != REDIS_REPLY_STATUS && strcmp(reply->str, "OK") != 0) {
    freeReplyObject(reply);
    throw std::runtime_error("redisCommand SET SessionID failed");
  }
  reply = (redisReply *)redisCommand(_redis, "SET BEV%d %b", _SessionID, &_bev,
                                     sizeof(bufferevent *));
  if (reply->type != REDIS_REPLY_STATUS && strcmp(reply->str, "OK") != 0) {
    freeReplyObject(reply);
    throw std::runtime_error("redisCommand SET BEV failed");
  }
  freeReplyObject(reply);

  _Registed = true;
  getSessionIDResponse(msg, len);
}

void FtProtocol::HandleSessionIDRequest(char *msg, int &len) {
  if (!_Registed || _transmitting) {
    len = 0;
    return;
  }
  uint16_t sessionID = *reinterpret_cast<uint16_t *>(msg + 4);
  redisReply *reply = (redisReply *)redisCommand(_redis, "GET %d", sessionID);

  if (reply->type == REDIS_REPLY_STRING) {
    if (reply->len != sizeof(NS)) {
      freeReplyObject(reply);
      throw std::runtime_error("redisCommand GET not match");
    }
    NS netStatus{};
    memcpy(&netStatus, reply->str, reply->len);
    getNetStatusResponse(msg, len, &netStatus);
    _targetSessionID = sessionID;
  } else {
    getNetStatusResponse(msg, len, nullptr);
  }
}

void FtProtocol::getSessionIDRequest(char *msg, int &len, uint16_t sessionID) {
  msg[0] = FT_MSG_CLASS_REQUEST;
  msg[1] = FT_MSG_TYPE_SESSIONID;
  *reinterpret_cast<uint16_t *>(msg + 2) = 2;
  *reinterpret_cast<uint16_t *>(msg + 4) = sessionID;
  len = 6;
}

void FtProtocol::getNetStatusResponse(char *msg, int &len, const NS *Ns) {
  msg[1] = FT_MSG_TYPE_NETSTATUS;
  if (Ns == nullptr) {
    msg[0] = FT_MSG_CLASS_NOTIFICATION;
    *reinterpret_cast<uint16_t *>(msg + 2) = 0;
    len = 4;
  } else {
    msg[0] = FT_MSG_CLASS_RESPONSE;
    *reinterpret_cast<uint16_t *>(msg + 2) = sizeof(NS);
    memcpy(msg + 4, Ns, sizeof(NS));
    len = 4 + sizeof(NS);
  }
}

void FtProtocol::setNetStatus(const char *msg, int len) {
  if (len != sizeof(NS) + 4)
    return;
  memcpy(&_Ns, msg + 4, sizeof(NS));
  redisReply *reply = (redisReply *)redisCommand(_redis, "SET %d %b",
                                                 _SessionID, &_Ns, sizeof(NS));
  if (reply->type != REDIS_REPLY_STATUS && strcmp(reply->str, "OK") != 0) {
    freeReplyObject(reply);
    throw std::runtime_error("redisCommand SET failed");
  }
  freeReplyObject(reply);
}

void FtProtocol::HandleSessionID(const char *msg, int len) {
  if (len != 6)
    return;
  _SessionID = *reinterpret_cast<const uint16_t *>(msg + 4);
}

void FtProtocol::HandleNetStatus(const char *msg, int len) {
  if (len != sizeof(NS) + 4)
    return;
  memcpy(&_Ns, msg + 4, sizeof(NS));
}

void FtProtocol::getNetStatusRequest(char *msg, int &len, const NS *Ns) {
  msg[0] = FT_MSG_CLASS_REQUEST;
  msg[1] = FT_MSG_TYPE_NETSTATUS;
  *reinterpret_cast<uint16_t *>(msg + 2) = sizeof(NS);
  memcpy(msg + 4, Ns, sizeof(NS));
  len = 4 + sizeof(NS);
}

// void Transmit(bufferevent *bev, void *ctx) {
//   thread_local char buf[4096];
//   int len = 0;
//   FtProtocol *ft = reinterpret_cast<FtProtocol *>(ctx);
//   while ((len = bufferevent_read(bev, buf, 4096)) > 0) {
//     TransferContext *transferCtx = new TransferContext();
//     char *data = new char[len];
//     memcpy(data, buf, len);
//     transferCtx->targetBev = ft->_targetBev;
//     transferCtx->data = data;
//     transferCtx->len = len;
//     {
//       std::lock_guard<std::mutex> lock(data_queue_mtx);
//       data_queue.push(transferCtx);
//     }
//     // std::cout<<"Transmit"<<getppid()<<std::endl;

//     // int statu = bufferevent_write(ft->_targetBev, buf, len);
//     // if (statu != 0) {
//     //   throw std::runtime_error("bufferevent_write failed");
//     // }
//     // send(bufferevent_getfd(ft->_targetBev), buf, len, 0);
//   }
//   event_active(ft->_callBackEvent, EV_WRITE, 0);
// }

void Transmit(bufferevent *bev, void *ctx) {
  FtProtocol *ft = reinterpret_cast<FtProtocol *>(ctx);
  struct evbuffer *input = bufferevent_get_input(bev);
  struct evbuffer *output = bufferevent_get_output(ft->_targetBev);
  evbuffer_add_buffer(output, input);
  // bufferevent_flush(ft->_targetBev, EV_WRITE, BEV_FLUSH);
}

void FtProtocol::HandleData(const char *msg, int len) {
  if (!_Registed || _transmitting || _targetSessionID == UINT16_MAX) {
    return;
  }
  _transmitting = true;
  redisReply *reply =
      (redisReply *)redisCommand(_redis, "GET BEV%d", _targetSessionID);
  if (reply->type != REDIS_REPLY_STRING) {
    freeReplyObject(reply);
    throw std::runtime_error("redisCommand GET BEV failed");
  }
  _targetBev = *reinterpret_cast<bufferevent **>(reply->str);
  freeReplyObject(reply);

  bufferevent_event_cb eventcb_ptr;
  void *cbarg_ptr;
  bufferevent_getcb(_bev, nullptr, nullptr, &eventcb_ptr, &cbarg_ptr);
  bufferevent_setcb(_bev, Transmit, nullptr, eventcb_ptr, cbarg_ptr);
}

void FtProtocol::getDataRequest(char *msg, int &len) {
  msg[0] = FT_MSG_CLASS_REQUEST;
  msg[1] = FT_MSG_TYPE_DATA;
  *reinterpret_cast<uint16_t *>(msg + 2) = 0;
  len = 4;
}