

file(GLOB FTPROTOCOL_SRC "*.cpp")
add_library(ft STATIC ${FTPROTOCOL_SRC})
target_link_libraries(ft hiredis)