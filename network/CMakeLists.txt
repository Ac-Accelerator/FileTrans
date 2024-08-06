file(GLOB NETWORK_SRC "*.cpp")
add_library(network STATIC ${NETWORK_SRC})
target_link_libraries(network PUBLIC event)