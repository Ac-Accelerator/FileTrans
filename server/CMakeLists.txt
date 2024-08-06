
file(GLOB SERVER_SRC "*.cpp")
add_executable(server  ${SERVER_SRC})
target_link_libraries(server PUBLIC network ft hiredis event_pthreads)
