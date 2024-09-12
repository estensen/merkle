package merkle

import (
	"errors"
	"hash"
)

var ErrNoLeaves = errors.New("cannot create a tree with no leaves")

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root     []byte
	Leaves   [][]byte
	HashFunc hash.Hash
}

// NewMerkleTree creates a new Merkle tree from the given leaves and hash function.
func NewMerkleTree(leaves [][]byte, hashFunc hash.Hash) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, ErrNoLeaves
	}

	tree := &MerkleTree{
		Leaves:   leaves,
		HashFunc: hashFunc,
	}

	tree.Root = tree.buildTree()

	return tree, nil
}

func (m *MerkleTree) buildTree() []byte {
	return []byte{}
}
