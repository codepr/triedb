TrieDB
=======

Multithreaded Key-value store based on a
[Trie](https://en.wikipedia.org/wiki/Trie) data structure. Trie is a kind of
trees in which each node is a prefix for a key, the node position define the
keys and the associated values are set on the last node of each key. They
provide a big-O runtime complexity of **O(m)** on worst case, for insertion and
lookup, where **m** is the length of the key. The main advantage is the
possibility to query the tree by prefix, executing range scans in an easy way.

Almost all commands supported has a "prefix" version which apply the command
itself on a prefix instead of a full key.

## Build

```sh
$ cmake .
$ make
```

Inside `bin/` directory will be placed `triedb` and `triedb_tests` executables.


## Under the hood

### The protocol

TrieDB uses a custom binary protocol to communicate, the structure of a packet
is pretty simple, it is formed by a 1 byte header, the size of the payload and
the payload itself.

```
    |  HEADER  |
    |----------|
    |    LEN   |
    |----------|
    |          |
    |  PAYLOAD |
    |          |
```

The header, as shown below, is formed by 4 MSB to define the `OPCODE` of the
command, 1 bit as a `PREFIX` flag for commands which supports `PREFIX` operations
(e.g. range queries) and the remaining are reserved for future uses (perhaps
distribution on cluster).
Bytes from 2 to 5 are used for storing the length, behaving much like MQTT
length algorithm, for every byte only the first 7 bits are used to store
values, the last one bit is just a flag indicating wether the size is stored
also in the next byte or not (so 127 as 1 byte, 16129 on 2 bytes and like
this).
```
    | Bit    | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
    |--------|---------------|---------------|
    | Byte 1 |     opcode    | p | reserved  |
    |--------|-------------------------------|
    | Byte 2 |                               |
    |  .     |      Remaning Length          |
    |  .     |                               |
    | Byte 5 |                               |
 ```

As written before, each TrieDB command is identified by the 7-4 bits of every
header which can be summarized by the following table:

```
     OPCODE |    BIN    | HEX
     -------|-----------|------
      PUT   | 00010000  | 0x10
      GET   | 00100000  | 0x20
      DEL   | 00110000  | 0x30
      TTL   | 01000000  | 0x40
      INC   | 01010000  | 0x50
      DEC   | 01100000  | 0x60
      CNT   | 01110000  | 0x70
      USE   | 10000000  | 0x80
      KEYS  | 10010000  | 0x90
      PING  | 10100000  | 0xa0
      QUIT  | 10110000  | 0xb0
      DB    | 11000000  | 0xc0
```

Header byte can be manipulated at bit level to toggle bit flags:
e.g

`PUT` with `PREFIX = 1 is 00010000 | (00010000 >> 1)  -> 00011000 -> 0x24`

## Changelog

See the [CHANGELOG](CHANGELOG) file.
