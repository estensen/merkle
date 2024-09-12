package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

var ErrNoLeaves = errors.New("cannot create a tree with no leaves")

// Node represents a node in the Merkle tree
type Node struct {
	Hash  []byte
	Value []byte
	Left  *Node
	Right *Node
}

func NewNode(hash, val []byte) *Node {
	return &Node{Hash: hash, Value: val}
}

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root     *Node
	Leaves   []*Node
	HashFunc hash.Hash
}

// NewMerkleTree creates a new Merkle tree from the given values and hash function.
func NewMerkleTree(values [][]byte, hashFunc hash.Hash) (*MerkleTree, error) {
	if len(values) == 0 {
		return nil, ErrNoLeaves
	}

	tree := &MerkleTree{
		HashFunc: hashFunc,
	}

	// Convert leaves into Nodes
	for _, val := range values {
		hashFunc.Write(val)
		hashedValue := hashFunc.Sum(nil)
		node := NewNode(hashedValue, val)
		tree.Leaves = append(tree.Leaves, node)
		hashFunc.Reset()
	}

	tree.Root = buildTree(tree.Leaves, hashFunc)

	return tree, nil
}

func buildTree(nodes []*Node, hashFunc hash.Hash) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *Node
		if i+1 < len(nodes) {
			right = nodes[i+1]
		}

		// Hash children to crate parent hash
		hashFunc.Write(left.Hash)
		if right != nil {
			hashFunc.Write(right.Hash)
		}
		parentHash := hashFunc.Sum(nil)
		hashFunc.Reset()

		parent := &Node{Hash: parentHash, Left: left, Right: right}
		parents = append(parents, parent)
	}

	return buildTree(parents, hashFunc)
}

func (m *MerkleTree) PrintTree() {
	if m.Root == nil {
		fmt.Println("Empty tree")
	} else {
		fmt.Print(m.Root.StringifyTree("", false))
	}
}

// StringifyTree creates an ASCII representations of the
// Merkle tree tha can be printed.
func (n *Node) StringifyTree(prefix string, isLeft bool) string {
	if n == nil {
		return ""
	}

	var result strings.Builder

	// Add current node (branch or leaf)
	if len(prefix) > 0 {
		if isLeft {
			result.WriteString(fmt.Sprintf("%s├── %s\n", prefix, hex.EncodeToString(n.Hash)))
		} else {
			result.WriteString(fmt.Sprintf("%s└── %s\n", prefix, hex.EncodeToString(n.Hash)))
		}
	} else {
		result.WriteString(fmt.Sprintf("%s\n", hex.EncodeToString(n.Hash)))
	}

	// Recursively stringify left and right subtrees
	newPrefix := prefix
	if isLeft {
		newPrefix += "│   "
	} else {
		newPrefix += "    "
	}

	if n.Left != nil || n.Right != nil {
		if n.Left != nil {
			result.WriteString(n.Left.StringifyTree(newPrefix, true))
		}
		if n.Right != nil {
			result.WriteString(n.Right.StringifyTree(newPrefix, false))
		}
	} else if n.Value != nil {
		// Add leaf value without extra indentation
		result.WriteString(fmt.Sprintf("%s    (Leaf Value: %s)\n", prefix, string(n.Value)))
	}

	return result.String()
}
