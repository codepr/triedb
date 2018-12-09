CC=gcc
CFLAGS=-std=c99 -Wall -lrt -pedantic -D_DEFAULT_SOURCE
RELEASE=../bin
SRC=../src/trie.c \
	../src/list.c \
	../src/ringbuf.c \
	structures_test.c \
	trie_test.c


test: $(SRC)
	mkdir -p $(RELEASE) && $(CC) $(CFLAGS) $(SRC) -o $(RELEASE)/trie_test && $(RELEASE)/trie_test
