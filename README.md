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
	tree, err := merkle.NewTree(leaves, sha256.New)
	if err != nil {
		panic(err)
	}

    // Print ASCII tree
	tree.PrintTree()

    // Generate proof for item
	proofItem := []byte("leaf2")
	proof, err := tree.GenerateProof(proofItem)
	if err != nil {
		panic(err)
	}

    // Validate proof
	isValid := tree.VerifyProof(proof, proofItem)
	if !isValid {
		fmt.Printf("%s is in the tree\n", proofItem)
	}
	fmt.Printf("%s is in the tree\n", proofItem)
}

```
