# merkle

A simple and efficient Merkle Tree implementation in Go, supporting common operations such as:

- Generating Merkle Proofs
- Verifying Merkle Proofs
- Updating leaves
- Printing the tree structure

## Installation

```bash
go get github.com/estensen/merkle
```

## Usage

```go
package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/estensen/merkle"
)

func main() {
	// Example leaves
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}

	// Create a Merkle tree with SHA-256
	hashFunc := sha256.New
	tree, _ := merkle.NewTree(leaves, hashFunc)

	// Print ASCII tree
	tree.PrintTree()

	// Generate proof for item
	proofItem := []byte("leaf2")
	proof, _ := tree.GenerateProof(proofItem)

	// Validate proof
	isValid, _ := tree.VerifyProof(proof, proofItem)
	if !isValid {
		fmt.Printf("%s is in the tree\n", proofItem)
	} else {
		fmt.Printf("%s is in the tree\n", proofItem)
	}
}
```

## Output

```
❯ go run cmd/main.go
c4e2cee656a5eba68e478af89e7e1ed9a0962b8496700eb0602d3540365871dd
    ├── cea713a5636f023630cde24d4f4ffd9cd2b5417d60af79304c6ba7427dfdbee1
    │   ├── d103cfb5e499c566904787533afbdec56f95492d67fc00e2c0d0161ba99653f1
    │       (Leaf Value: leaf1)
    │   └── 5038da95330ba16edb486954197e37eb777c3047327ca54df4199c35c5edc17a
    │       (Leaf Value: leaf2)
    └── 0a5cfafddf507f837a42ab41114edad84237e9799b95a8ab196be721055f8e75
        ├── f2764fd79fdab5132fc349ba555c9c56ff0c935c889c17ebe3d61315d780934e
            (Leaf Value: leaf3)
        └── 565fb0e0cefe32cf4000e4a67ddec8820111a733aa8ba010d242a5fe477e04c4
            (Leaf Value: leaf4)
leaf2 is in the tree

```
