#pragma once
#include "socket.h"
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <string>
#include <vector>

class SocketBufferEvent;
class SocketEventListener;

typedef void (*SocketBufferEvent_DATA_CB)(SocketBufferEvent *, void *);
typedef void (*SocketBufferEvent_EVENT_CB)(SocketBufferEvent *, short, void *);
typedef void (*SocketEventListener_CB)(SocketEventListener *, int, sockaddr *,
                                       int, void *);

class SocketEventConfig {
private:
  event_config *_config;

public:
  SocketEventConfig();
  ~SocketEventConfig();
  SocketEventConfig(const SocketEventConfig &) = delete;
  SocketEventConfig &operator=(const SocketEventConfig &) = delete;

  void avoidMethod(const std::string &method);

  void requireFeatures(int feature);

  void setFlag(event_base_config_flag flag);

  void priorityInit(int npriorities);

  friend class SocketEventBase;
};

class SocketEventBase {
private:
  event_base *_base;

public:
  SocketEventBase();
  SocketEventBase(const SocketEventConfig &config);
  ~SocketEventBase();
  SocketEventBase(const SocketEventBase &) = delete;
  SocketEventBase &operator=(const SocketEventBase &) = delete;

  std::vector<std::string> getSupportedMethods() const;
  std::string getMethod() const;
  event_method_feature getFeatures() const;

  int loop(int flags);
  int loopBreak();
  int loopExit(const timeval &tv);
  int loopContinue();
  int dispatch();

  bool gotExit() const;
  bool gotBreak() const;

  int foreachEvent(event_base_foreach_event_cb fn, void *arg) const;

  friend class SocketEvent;
  friend class SocketBufferEvent;
  friend class SocketEventListener;
};

class SocketEvent {
private:
  event *_event;
  const SocketEventBase &_base;

public:
  SocketEvent(const SocketEventBase &base, Socket &&socket, short events,
              event_callback_fn callback, void *arg);
  ~SocketEvent();

  SocketEvent(const SocketEvent &) = delete;
  SocketEvent &operator=(const SocketEvent &) = delete;

  void add(const timeval &tv);
  void del();
  void removeTimer();
  void prioritySet(int priority);
  bool pending(short events, timeval &tv) const;
  int getFd() const;
  SocketEventBase &getBase() const;
  short getEvents() const;
  event_callback_fn getCallback() const;
  void *getCallbackArg() const;
  int getPriority() const;
};

class SocketBufferEvent {
private:
  bufferevent *_bufferEvent;
  const SocketEventBase &_base;

  SocketBufferEvent_DATA_CB _readCb = nullptr;
  SocketBufferEvent_DATA_CB _writeCb = nullptr;
  SocketBufferEvent_EVENT_CB _eventCb = nullptr;
  struct Args {
    SocketBufferEvent *thisptr;
    void *arg;
  } _cbarg;

public:
  SocketBufferEvent(const SocketEventBase &base, Socket &&socket, int options);
  SocketBufferEvent(const SocketEventBase &base, int options);
  ~SocketBufferEvent();
  SocketBufferEvent(const SocketBufferEvent &) = delete;
  SocketBufferEvent &operator=(const SocketBufferEvent &) = delete;

  const SocketEventBase &getBase() const;

  void connect(const sockaddr *addr, int addrlen);
  void connect(uint32_t ip, uint16_t port);
  void connect(const std::string &HostName, uint16_t port);

  void setCallbacks(SocketBufferEvent_DATA_CB readCb,
                    SocketBufferEvent_DATA_CB writeCb,
                    SocketBufferEvent_EVENT_CB eventCb, void *cbarg);

  void getCallbacks(SocketBufferEvent_DATA_CB *readCb,
                    SocketBufferEvent_DATA_CB *writeCb,
                    SocketBufferEvent_EVENT_CB *eventCb, void **cbarg) const;

  void enable(short events);
  void disable(short events);
  short getEnabled() const;
  void setWatermark(short events, size_t lowmark, size_t highmark);
  void write(const void *data, size_t size);
  size_t read(void *data, size_t size);
  int flush(short iotype, bufferevent_flush_mode mode);

  void setPriority(int priority);
  int getPriority() const;

  friend void SocketBufferEvent_readCallback(struct bufferevent *bev,
                                             void *ctx);
  friend void SocketBufferEvent_writeCallback(struct bufferevent *bev,
                                              void *ctx);
  friend void SocketBufferEvent_eventCallback(struct bufferevent *bev,
                                              short events, void *ctx);
};

class SocketEventListener {
private:
  evconnlistener *_listener;
  const SocketEventBase &_base;

  SocketEventListener_CB _cb;

  struct Args {
    SocketEventListener *thisptr;
    void *arg;
  } _cbarg;

public:
  SocketEventListener(const SocketEventBase &base, SocketEventListener_CB cb,
                      void *ptr, int flags, int backlog, Socket &&socket);

  ~SocketEventListener();
  SocketEventListener(const SocketEventListener &) = delete;
  SocketEventListener &operator=(const SocketEventListener &) = delete;

  void enable();
  void disable();
  void setCallbacks(SocketEventListener_CB cb, void *ptr);
  int getFd() const;
  const SocketEventBase &getBase() const;

  friend void SocketEventListener_callback(struct evconnlistener *listener,
                                           evutil_socket_t fd, sockaddr *addr,
                                           int socklen, void *ctx);
};