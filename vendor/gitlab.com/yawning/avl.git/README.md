### AVL - AVL tree
#### Yawning Angel (yawning at schwanenlied dot me)

[![GoDoc](https://godoc.org/git.schwanenlied.me/yawning/avl.git?status.svg)](https://godoc.org/git.schwanenlied.me/yawning/avl.git)

A generic Go AVL tree implementation, derived from [Eric Biggers' C code][1],
in the spirt of [the runtime library's containers][2].

Features:

 * Size
 * Insertion
 * Deletion
 * Search
 * In-order traversal (forward and backward) with an iterator or callback.
 * Non-recursive.

Note:

 * The package itself is free from external dependencies, the unit tests use
   [testify][3].

[1]: https://github.com/ebiggers/avl_tree
[2]: https://golang.org/pkg/container
[3]: https://github.com/stretchr/testify
