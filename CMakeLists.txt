cmake_minimum_required(VERSION 2.8)

project(tritedb)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -std=c11 -lpthread -O3 -pedantic -D_DEFAULT_SOURCE -ggdb -fsanitize=address -fno-omit-frame-pointer -pg")
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

file(GLOB SOURCES src/*.c)
file(GLOB TEST src/list.c src/trie.c src/util.c src/server.c src/network.c src/protocol.c src/ringbuf.c tests/*.c)

# Executable
add_executable(tritedb_test ${TEST})
add_executable(tritedb ${SOURCES})
# Tests
add_test(tritedb_test bin/tritedb_test)
