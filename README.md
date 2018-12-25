TriteDB
=======

Single threaded Key-value store based on a
[Trie](https://en.wikipedia.org/wiki/Trie) data structure.  Trie is a special
kind of trees in which each node is a prefix for a key, the node position
define the keys and the associated values are set on the last node of each key.
They provide a big-O runtime complexity of O(m) on worst case, for insertion
and lookup, where m is the length of the key.

## Build

```sh
$ cmake .
$ make
```

Inside `/bin` directory will be placed `tritedb` and `tritedb_tests` executables.


## Changelog

See the [CHANGELOG](CHANGELOG) file.
