package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/estensen/merkle"
)

func main() {
	// Example leaves
	leaves := [][]byte{
		[]byte("yolo"),
		[]byte("diftp"),
		[]byte("ngmi"),
		[]byte("lfg"),
	}

	// Initialize a Merkle tree with SHA-256
	hashFunc := sha256.New()
	tree, err := merkle.NewTree(leaves, hashFunc)
	if err != nil {
		fmt.Printf("Failed to create Merkle tree: %v\n", err)
		return
	}

	tree.PrintTree()

	proof, err := tree.GenerateProof([]byte("diftp"))
	if err != nil {
		panic(err)
	}

	isValid := tree.VerifyProof(proof, []byte("diftp"))
	if !isValid {
		panic("failed to verify proof for diftp")
	}
	fmt.Println("diftp is in the tree")
}
