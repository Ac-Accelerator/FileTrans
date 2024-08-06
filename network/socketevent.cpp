#include "socketevent.h"
#include "socketv4.h"
#include <stdexcept>

void SocketBufferEvent_readCallback(struct bufferevent *bev, void *ctx) {
  SocketBufferEvent::Args *args =
      reinterpret_cast<SocketBufferEvent::Args *>(ctx);
  if (args->thisptr->_readCb != nullptr) {
    args->thisptr->_readCb(args->thisptr, args->arg);
  }
}

void SocketBufferEvent_writeCallback(struct bufferevent *bev, void *ctx) {
  SocketBufferEvent::Args *args =
      reinterpret_cast<SocketBufferEvent::Args *>(ctx);
  if (args->thisptr->_writeCb != nullptr) {
    args->thisptr->_writeCb(args->thisptr, args->arg);
  }
}

void SocketBufferEvent_eventCallback(struct bufferevent *bev, short events,
                                     void *ctx) {
  SocketBufferEvent::Args *args =
      reinterpret_cast<SocketBufferEvent::Args *>(ctx);
  if (args->thisptr->_eventCb != nullptr) {
    args->thisptr->_eventCb(args->thisptr, events, args->arg);
  }
}

void SocketEventListener_callback(struct evconnlistener *listener,
                                  evutil_socket_t fd, sockaddr *addr,
                                  int socklen, void *ctx) {
  SocketEventListener::Args *args =
      reinterpret_cast<SocketEventListener::Args *>(ctx);
  if (args->thisptr->_cb != nullptr) {
    args->thisptr->_cb(args->thisptr, fd, addr, socklen, args->arg);
  }
}

// SocketEventConfig

SocketEventConfig::SocketEventConfig() {
  _config = event_config_new();
  if (_config == nullptr) {
    throw std::runtime_error("Failed to create event_config");
  }
}

SocketEventConfig::~SocketEventConfig() {
  if (_config != nullptr) {
    event_config_free(_config);
  }
}

void SocketEventConfig::avoidMethod(const std::string &method) {
  if (event_config_avoid_method(_config, method.c_str()) != 0) {
    throw std::runtime_error("Failed to avoid method");
  }
}

void SocketEventConfig::requireFeatures(int feature) {
  if (event_config_require_features(_config, feature) != 0) {
    throw std::runtime_error("Failed to require features");
  }
}

void SocketEventConfig::setFlag(event_base_config_flag flag) {
  if (event_config_set_flag(_config, flag) != 0) {
    throw std::runtime_error("Failed to set flag");
  }
}

// SocketEventBase

SocketEventBase::SocketEventBase() {
  _base = event_base_new();
  if (_base == nullptr) {
    throw std::runtime_error("Failed to create event_base");
  }
}

SocketEventBase::SocketEventBase(const SocketEventConfig &config) {
  _base = event_base_new_with_config(config._config);
  if (_base == nullptr) {
    throw std::runtime_error("Failed to create event_base");
  }
}

SocketEventBase::~SocketEventBase() {
  if (_base != nullptr) {
    event_base_free(_base);
  }
}

std::vector<std::string> SocketEventBase::getSupportedMethods() const {
  const char **methods = event_get_supported_methods();
  std::vector<std::string> result;
  for (const char **method = methods; *method != nullptr; ++method) {
    result.push_back(std::string(*method));
  }
  return result;
}

std::string SocketEventBase::getMethod() const {
  return std::string(event_base_get_method(_base));
}

event_method_feature SocketEventBase::getFeatures() const {
  return static_cast<event_method_feature>(event_base_get_features(_base));
}

int SocketEventBase::loop(int flags) {
  int ret = event_base_loop(_base, flags);
  if (ret == -1) {
    throw std::runtime_error("Failed to loop");
  }
  return ret;
}

int SocketEventBase::loopBreak() {
  int ret = event_base_loopbreak(_base);
  if (ret == -1) {
    throw std::runtime_error("Failed to break loop");
  }
  return ret;
}

int SocketEventBase::loopExit(const timeval &tv) {
  int ret = event_base_loopexit(_base, &tv);
  if (ret == -1) {
    throw std::runtime_error("Failed to exit loop");
  }
  return ret;
}

int SocketEventBase::loopContinue() {
  int ret = event_base_loopcontinue(_base);
  if (ret == -1) {
    throw std::runtime_error("Failed to continue loop");
  }
  return ret;
}

int SocketEventBase::dispatch() {
  int ret = event_base_dispatch(_base);
  if (ret == -1) {
    throw std::runtime_error("Failed to dispatch");
  }
  return ret;
}

bool SocketEventBase::gotExit() const { return event_base_got_exit(_base); }

bool SocketEventBase::gotBreak() const { return event_base_got_break(_base); }

int SocketEventBase::foreachEvent(event_base_foreach_event_cb fn,
                                  void *arg) const {
  return event_base_foreach_event(_base, fn, arg);
}

// SocketEvent

SocketEvent::SocketEvent(const SocketEventBase &base, Socket &&socket,
                         short events, event_callback_fn callback, void *arg)
    : _base(base) {
  _event = event_new(base._base, socket.getFd(), events, callback, arg);
  if (_event == nullptr) {
    throw std::runtime_error("Failed to create event");
  }
}

SocketEvent::~SocketEvent() {
  if (_event != nullptr) {
    event_free(_event);
  }
}

void SocketEvent::add(const timeval &tv) {
  if (event_add(_event, &tv) != 0) {
    throw std::runtime_error("Failed to add event");
  }
}

void SocketEvent::del() {
  if (event_del(_event) != 0) {
    throw std::runtime_error("Failed to delete event");
  }
}

void SocketEvent::removeTimer() {
  if (event_remove_timer(_event) != 0) {
    throw std::runtime_error("Failed to remove timer");
  }
}

void SocketEvent::prioritySet(int priority) {
  if (event_priority_set(_event, priority) != 0) {
    throw std::runtime_error("Failed to set priority");
  }
}

bool SocketEvent::pending(short events, timeval &tv) const {
  return event_pending(_event, events, &tv);
}

int SocketEvent::getFd() const { return event_get_fd(_event); }

SocketEventBase &SocketEvent::getBase() const {
  return const_cast<SocketEventBase &>(_base);
}

short SocketEvent::getEvents() const { return event_get_events(_event); }

event_callback_fn SocketEvent::getCallback() const {
  return event_get_callback(_event);
}

void *SocketEvent::getCallbackArg() const {
  return event_get_callback_arg(_event);
}

int SocketEvent::getPriority() const { return event_get_priority(_event); }

// SocketBufferEvent

SocketBufferEvent::SocketBufferEvent(const SocketEventBase &base,
                                     Socket &&socket, int options)
    : _base(base) {
  socket.unblock();
  _bufferEvent = bufferevent_socket_new(base._base, socket.getFd(), options);
  if (_bufferEvent == nullptr) {
    throw std::runtime_error("Failed to create buffer event");
  }
}

SocketBufferEvent::SocketBufferEvent(const SocketEventBase &base, int options)
    : _base(base) {
  _bufferEvent =
      bufferevent_socket_new(base._base, -1, BEV_OPT_CLOSE_ON_FREE | options);
}

SocketBufferEvent::~SocketBufferEvent() {
  if (_bufferEvent != nullptr) {
    bufferevent_free(_bufferEvent);
  }
}

const SocketEventBase &SocketBufferEvent::getBase() const { return _base; }

void SocketBufferEvent::connect(const sockaddr *addr, int addrlen) {
  if (bufferevent_socket_connect(_bufferEvent, addr, addrlen) != 0) {
    throw std::runtime_error("Failed to connect buffer event");
  }
}

void SocketBufferEvent::connect(uint32_t ip, uint16_t port) {
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(ip);
  addr.sin_port = htons(port);
  connect(reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
}

void SocketBufferEvent::connect(const std::string &host, uint16_t port) {
  uint32_t ip = resolveHost(host);
  connect(ip, port);
}

void SocketBufferEvent::setCallbacks(SocketBufferEvent_DATA_CB readCb,
                                     SocketBufferEvent_DATA_CB writeCb,
                                     SocketBufferEvent_EVENT_CB eventCb,
                                     void *cbarg) {
  _readCb = readCb;
  _writeCb = writeCb;
  _eventCb = eventCb;
  _cbarg.thisptr = this;
  _cbarg.arg = cbarg;
  bufferevent_setcb(_bufferEvent, SocketBufferEvent_readCallback,
                    SocketBufferEvent_writeCallback,
                    SocketBufferEvent_eventCallback, &_cbarg);
}

void SocketBufferEvent::getCallbacks(SocketBufferEvent_DATA_CB *readCb,
                                     SocketBufferEvent_DATA_CB *writeCb,
                                     SocketBufferEvent_EVENT_CB *eventCb,
                                     void **cbarg) const {
  *readCb = _readCb;
  *writeCb = _writeCb;
  *eventCb = _eventCb;
}

void SocketBufferEvent::enable(short events) {
  if (bufferevent_enable(_bufferEvent, events) != 0) {
    throw std::runtime_error("Failed to enable buffer event");
  }
}

void SocketBufferEvent::disable(short events) {
  if (bufferevent_disable(_bufferEvent, events) != 0) {
    throw std::runtime_error("Failed to disable buffer event");
  }
}

short SocketBufferEvent::getEnabled() const {
  return bufferevent_get_enabled(_bufferEvent);
}

void SocketBufferEvent::setWatermark(short events, size_t lowmark,
                                     size_t highmark) {
  bufferevent_setwatermark(_bufferEvent, events, lowmark, highmark);
}

void SocketBufferEvent::write(const void *data, size_t size) {
  if (bufferevent_write(_bufferEvent, data, size) != 0) {
    throw std::runtime_error("Failed to write buffer event");
  }
}

size_t SocketBufferEvent::read(void *data, size_t size) {
  return bufferevent_read(_bufferEvent, data, size);
}

int SocketBufferEvent::flush(short iotype, bufferevent_flush_mode mode) {
  int ret = bufferevent_flush(_bufferEvent, iotype, mode);
  if (ret == -1) {
    throw std::runtime_error("Failed to flush buffer event");
  }
  return ret;
}

void SocketBufferEvent::setPriority(int priority) {
  if (bufferevent_priority_set(_bufferEvent, priority) != 0) {
    throw std::runtime_error("Failed to set priority");
  }
}

int SocketBufferEvent::getPriority() const {
  return bufferevent_get_priority(_bufferEvent);
}

// SocketEventListener

SocketEventListener::SocketEventListener(const SocketEventBase &base,
                                         SocketEventListener_CB cb, void *ptr,
                                         int flags, int backlog, Socket &&socket)
    : _base(base) {
  _cb = cb;
  _cbarg.thisptr = this;
  _cbarg.arg = ptr;
  _listener = evconnlistener_new(base._base, SocketEventListener_callback,
                                 &_cbarg, flags, backlog, socket.getFd());
  if (_listener == nullptr) {
    throw std::runtime_error("Failed to create listener");
  }
}

SocketEventListener::~SocketEventListener() {
  if (_listener != nullptr) {
    evconnlistener_free(_listener);
  }
}

void SocketEventListener::enable() {
  if (evconnlistener_enable(_listener) != 0) {
    throw std::runtime_error("Failed to enable listener");
  }
}

void SocketEventListener::disable() {
  if (evconnlistener_disable(_listener) != 0) {
    throw std::runtime_error("Failed to disable listener");
  }
}

void SocketEventListener::setCallbacks(SocketEventListener_CB cb, void *ptr) {
  _cb = cb;
}

int SocketEventListener::getFd() const {
  return evconnlistener_get_fd(_listener);
}

const SocketEventBase &SocketEventListener::getBase() const { return _base; }