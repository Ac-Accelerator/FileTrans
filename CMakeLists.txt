cmake_minimum_required(VERSION 3.10)
project(FileTrans)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache) # Less useful to do it for linking, see edit2
endif(CCACHE_FOUND)

include_directories(network)
include_directories(stunprotocol)
include_directories(ftprotocol)
include_directories(hiredis)


add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(network)
add_subdirectory(stunprotocol)
add_subdirectory(ftprotocol)
add_subdirectory(hiredis)

