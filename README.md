TrieDB
=======

Multithreaded Key-value store based on a
[Trie](https://en.wikipedia.org/wiki/Trie) data structure. Trie is a kind of
trees in which each node is a prefix for a key, the node position define the
keys and the associated values are set on the last node of each key. They
provide a big-O runtime complexity of **O(m)** on worst case, for insertion and
lookup, where **m** is the length of the key. The main advantage is the
possibility to query the tree by prefix, executing range scans in an easy way,
while also maintaining the keyspace ordered.

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
     OPCODE |    BIN    | HEX  | OPCODE  |
     -------|-----------|----------------|
      ACK   | 00000000  | 0x00 |    0    |
      PUT   | 00010000  | 0x10 |    1    |
      GET   | 00100000  | 0x20 |    2    |
      DEL   | 00110000  | 0x30 |    3    |
      TTL   | 01000000  | 0x40 |    4    |
      INC   | 01010000  | 0x50 |    5    |
      DEC   | 01100000  | 0x60 |    6    |
      CNT   | 01110000  | 0x70 |    7    |
      USE   | 10000000  | 0x80 |    8    |
      KEYS  | 10010000  | 0x90 |    9    |
      PING  | 10100000  | 0xa0 |    10   |
      QUIT  | 10110000  | 0xb0 |    11   |
      DB    | 11000000  | 0xc0 |    12   |
      INFO  | 11010000  | 0xd0 |    13   |
      FLUSH | 11100000  | 0xe0 |    14   |
      JOIN  | 11110000  | 0xf0 |    15   |
```

Header byte can be manipulated at bit level to toggle bit flags:
e.g

`PUT` with `PREFIX = 1 is 00010000 | (00010000 >> 1)  -> 00011000 -> 0x24`

### The server

TrieDB server module define a classic TCP server, based on I/O multiplexing but
sharing I/O and work loads between thread pools. The main thread have the
exclusive responsibility of accepting connections and pass them to IO threads.
From now on read and write operations for the connection will be handled by a
dedicated thread pool, which after every read will decode the bytearray
according to the protocol definition of each packet and finally pass the
resulting packet to the worker thread pool, where, according to the OPCODE of
the packet, the operation will be executed and the result will be returned back
to the IO thread that will write back to the client the response packed into a
bytestream.

```
       MAIN              1...N              1...N

      [EPOLL]         [IO EPOLL]         [WORK EPOLL]
   ACCEPT THREAD    IO THREAD POOL    WORKER THREAD POOL
   -------------    --------------    ------------------
         |                 |                  |
       ACCEPT              |                  |
         | --------------> |                  |
         |          READ AND DECODE           |
         |                 | ---------------> |
         |                 |                WORK
         |                 | <--------------- |
         |               WRITE                |
         |                 |                  |
       ACCEPT              |                  |
         | --------------> |                  |
```
By tuning the number of IO threads and worker threads based on the number of
core of the host machine, it is possible to increase the number of served
concurrent requests per seconds.

The underlying Trie data strucure accessed on the worker thread, in case of
multiple worker threads it' s guarded by a spinlock, and being generally fast
operations it shouldn't suffer high contentions by the threads and thus being
really fast. It's a poor model of concurrency for the computation part but as
of now it should be more than enough.

## Changelog

See the [CHANGELOG](CHANGELOG) file.
