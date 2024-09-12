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
	}

	// Initialize a Merkle tree with SHA-256
	hashFunc := sha256.New()
	_, err := merkle.NewMerkleTree(leaves, hashFunc)
	if err != nil {
		fmt.Printf("Failed to create Merkle tree: %v\n", err)
		return
	}
}
