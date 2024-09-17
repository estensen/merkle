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
	isValid, _ := merkle.VerifyProof(proof, proofItem, hashFunc(), tree.Root.Hash)
	if !isValid {
		fmt.Printf("%s is in the tree\n", proofItem)
	} else {
		fmt.Printf("%s is in the tree\n", proofItem)
	}
}

```
