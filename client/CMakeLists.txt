
# file(GLOB CLIENT_SRC "*.cpp")
add_executable(client main.cpp quic.c)
target_link_libraries(client network stun ft ssl crypto )

target_link_libraries(client ${CMAKE_SOURCE_DIR}/msquic/bin/libmsquic.so.2.3.6)
