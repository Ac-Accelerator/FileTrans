#pragma once
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>

class ThreadPool {
public:
  ThreadPool(size_t thread_count);
  ~ThreadPool();
  int pipe_fd[2];

  void enqueue(int socket_fd);
  void stop();

private:
  std::vector<std::thread> workers;
  static std::atomic<bool> stop_flag;

  void worker_thread();
  void process_socket(int socket_fd);

  static void HandleStop(evutil_socket_t fd, short evt, void *arg);
};

