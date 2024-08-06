
file(GLOB CLIENT_SRC "*.cpp")
add_executable(client ${CLIENT_SRC})
target_link_libraries(client network stun ft)