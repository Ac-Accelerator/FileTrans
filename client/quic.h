#pragma once
extern "C" {
int Client(const char *Target, int fd);
int Server(int fd);
}