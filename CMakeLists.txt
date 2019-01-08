cmake_minimum_required(VERSION 2.8)

project(tritedb)

OPTION(DEBUG "add debug flags" OFF)

if (DEBUG)
    message(STATUS "Configuring build for debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -std=c11 -lpthread -O3 -pedantic -D_DEFAULT_SOURCE -luuid -ggdb -fsanitize=address -fno-omit-frame-pointer -pg")
else (DEBUG)
    message(STATUS "Configuring build for production")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -std=c11 -lpthread -O3 -pedantic -D_DEFAULT_SOURCE -luuid")
endif (DEBUG)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

file(GLOB SOURCES src/*.c)
file(GLOB TEST src/hashtable.c src/vector.c src/config.c src/list.c src/trie.c src/util.c src/server.c src/network.c src/protocol.c src/ringbuf.c tests/*.c)

list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/tritedbcli.c)

set(AUTHOR "Andrea Giacomo Baldan")
set(LICENSE "BSD2 license")

# Executable
add_executable(tritedb_test ${TEST})
add_executable(tritedb ${SOURCES})
add_executable(tritedbcli src/config.c src/util.c src/tritedbcli.c)

add_custom_command(
    TARGET tritedb_test
    POST_BUILD
    COMMAND ${CMAKE_BINARY_DIR}/tritedb_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "\n Running tests")

# Tests
add_test(tritedb_test bin/tritedb_test)
