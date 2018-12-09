CC=gcc
CFLAGS=-std=c11 -Wall -lrt -lpthread -O3 -pedantic -D_DEFAULT_SOURCE
DEBUGFLAGS=-ggdb -fsanitize=address -fno-omit-frame-pointer -pg
ADDITIONAL=-fsanitize=undefined
BIN=./bin
SRC=src/trie.c \
	src/list.c \
	src/network.c \
	src/protocol.c \
	src/ringbuf.c \
	src/server.c \
	src/util.c

tritedb: $(SRC)
	mkdir -p $(BIN) && $(CC) $(CFLAGS) $(SRC) src/main.c -o $(BIN)/tritedb

debug:
	mkdir -p $(BIN) && $(CC) $(CFLAGS) $(DEBUGFLAGS) $(SRC) src/main.c -o $(BIN)/tritedb

test:
	cd tests && $(MAKE) test

clean:
	rm -f $(BIN)/*
