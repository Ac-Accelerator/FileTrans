
file(GLOB STUN_SRC "*.cpp")
add_library(stun STATIC ${STUN_SRC})
target_link_libraries(stun network)