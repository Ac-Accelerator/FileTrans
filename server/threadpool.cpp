#include "threadpool.h"
#include "ft.h"
#include "hiredis.h"
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <mutex>

thread_local redisContext *rc = nullptr;

static int FindAllEvents(const struct event_base *base, const struct event *ev,
                         void *arg) {
  std::vector<event *> events = *reinterpret_cast<std::vector<event *> *>(arg);
  events.push_back(const_cast<event *>(ev));
  return 0;
}

void HandleSocket(struct bufferevent *bev, void *ctx) {
  thread_local char buf[4096];
  int len = bufferevent_read(bev, buf, 4096);
  if (len > 0) {
    FtProtocol *ft = reinterpret_cast<FtProtocol *>(ctx);
    if (ft->processMessage(buf, len) == 0 && len > 0) {
      bufferevent_write(bev, buf, len);
    }
  }
}

void HandleEvent(struct bufferevent *bev, short what, void *ctx) {
  if (what & BEV_EVENT_EOF || what & BEV_EVENT_ERROR) {
    std::cout << "Connection closed" << std::endl;
    FtProtocol *ft = reinterpret_cast<FtProtocol *>(ctx);
    if (ft != nullptr) {
      if (ft->getTargetBev() != nullptr) {
        bufferevent_trigger_event(ft->getTargetBev(), BEV_EVENT_EOF, 0);
      }
      delete ft;
    }
    bufferevent_free(bev);
  }
}

void GetFromPipe(evutil_socket_t fd, short events, void *arg) {
  static std::mutex mtx;
  if (!mtx.try_lock()) {
    return;
  }
  event *ev = reinterpret_cast<event *>(arg);
  event_base *base = event_get_base(ev);
  int socket_fd;
  if (read(fd, &socket_fd, sizeof(socket_fd)) == sizeof(socket_fd)) {

    std::cout << "Received socket_fd: " << socket_fd << std::endl;

    fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    bufferevent *new_ev = bufferevent_socket_new(
        base, socket_fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

    FtProtocol *ft = new FtProtocol(rc, new_ev);
    bufferevent_setcb(new_ev, HandleSocket, nullptr, HandleEvent, ft);
    // bufferevent_setwatermark(new_ev, EV_WRITE, 0, 0);
    bufferevent_enable(new_ev, EV_READ | EV_WRITE);
  }
  mtx.unlock();
}

// ThreadPool ///////////////

std::atomic<bool> ThreadPool::stop_flag = false;

ThreadPool::ThreadPool(size_t thread_count) {
  for (size_t i = 0; i < thread_count; ++i) {
    workers.emplace_back(&ThreadPool::worker_thread, this);
  }

  // 创建管道用于控制工作线程
  if (pipe(pipe_fd) == -1) {
    throw std::runtime_error("Failed to create pipe");
  }

  fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
  fcntl(pipe_fd[1], F_SETFL, O_NONBLOCK);
}

ThreadPool::~ThreadPool() {
  stop();
  close(pipe_fd[0]);
  close(pipe_fd[1]);
}

void ThreadPool::enqueue(int socket_fd) {
  write(pipe_fd[1], &socket_fd, sizeof(socket_fd));
}

void ThreadPool::stop() {
  stop_flag.store(true);
  for (auto &worker : workers) {
    worker.join();
  }
}

void ThreadPool::worker_thread() {
  timeval tv = {5, 0};
  rc = redisConnectWithTimeout("127.0.0.1", 6379, tv);
  if (rc == nullptr || rc->err) {
    if (rc) {
      std::cout << "Connection error: " << rc->errstr << std::endl;
      redisFree(rc);
    } else {
      std::cout << "Connection error: can't allocate redis context"
                << std::endl;
    }
    return;
  }

  event_config *config = event_config_new();
  event_config_require_features(config, EV_FEATURE_FDS);
  event_base *base = event_base_new_with_config(config);
  event_config_free(config);

  struct event *ev = event_new(base, pipe_fd[0], EV_READ | EV_PERSIST,
                               GetFromPipe, event_self_cbarg());

  struct event *evt = evtimer_new(base, this->HandleStop, event_self_cbarg());

  event_add(ev, nullptr);
  evtimer_add(evt, &tv);

  event_base_dispatch(base);

  event_free(ev);
  event_free(evt);
  event_base_free(base);
  redisFree(rc);
}

void ThreadPool::HandleStop(evutil_socket_t fd, short evt, void *arg) {
  if (stop_flag.load()) {
    std::vector<event *> events;
    event *ev = reinterpret_cast<event *>(arg);
    event_base *base = event_get_base(ev);
    event_base_foreach_event(base, FindAllEvents, &events);
    for (auto ev : events) {
      event_free(ev);
    }
    event_base_loopbreak(base);
  }
}
