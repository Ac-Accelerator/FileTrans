#include "socketevent.h"
#include "socketv4.h"
#include "threadpool.h"
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

void AcceptNew(SocketEventListener *sel, int fd, sockaddr *addr, int socklen,
               void *ctx) {
  ThreadPool *pool = reinterpret_cast<ThreadPool *>(ctx);
  pool->enqueue(fd);
}

int main() {
  evthread_use_pthreads();

  ThreadPool pool(4); // 创建一个包含4个工作线程的线程池
  // 主线程接收新的连接
  IPv4Socket socket(SocketType::Stream, 0);
  int enable = 1;
  socket.setsockopt_socket(SocketOpt::REUSEADDR, &enable, sizeof(int));
  socket.bind(uint32_t(0), 25566);
  socket.unblock();
  SocketEventBase base;
  SocketEventListener listener(base, AcceptNew, &pool, LEV_OPT_CLOSE_ON_FREE,
                               -1, std::move(socket));
  listener.enable();
  base.dispatch();

  return 0;
}
