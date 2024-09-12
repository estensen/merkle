package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
)

var (
	ErrNoLeaves         = errors.New("cannot create a tree with no leaves")
	ErrNoVal            = errors.New("value not found in the tree")
	ErrIndexOutOfBounds = errors.New("index out of bounds")
)

// Node represents a node in the Merkle tree
type Node struct {
	Left  *Node
	Right *Node
	Hash  []byte
	Value []byte
}

func NewNode(hash, val []byte) *Node {
	return &Node{Hash: hash, Value: val}
}

// Tree represents a Merkle tree
type Tree struct {
	Root     *Node
	HashFunc hash.Hash
	Leaves   []*Node
}

// NewTree creates a new Merkle tree from the given values and hash function.
func NewTree(values [][]byte, hashFunc hash.Hash) (*Tree, error) {
	if len(values) == 0 {
		return nil, ErrNoLeaves
	}

	// Convert leaves into Nodes
	nodes := make([]*Node, 0, len(values))
	for _, val := range values {
		hashFunc.Write(val)
		hashedValue := hashFunc.Sum(nil)
		node := NewNode(hashedValue, val)
		nodes = append(nodes, node)
		hashFunc.Reset()
	}

	tree := &Tree{
		HashFunc: hashFunc,
	}
	tree.Root = buildTree(nodes, hashFunc)
	tree.Leaves = nodes

	return tree, nil
}

func buildTree(nodes []*Node, hashFunc hash.Hash) *Node {
	for len(nodes) > 1 {
		parents := make([]*Node, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right *Node
			if i+1 < len(nodes) {
				right = nodes[i+1]
			}
			hashFunc.Write(left.Hash)
			if right != nil {
				hashFunc.Write(right.Hash)
			}
			parentHash := hashFunc.Sum(nil)
			hashFunc.Reset()
			parents = append(parents, &Node{Hash: parentHash, Left: left, Right: right})
		}
		nodes = parents
	}
	return nodes[0]
}

// AddLeaf adds a new lead to the Merkle tree and recalculates
// the tree.
func (m *Tree) AddLeaf(value []byte) {
	m.HashFunc.Write(value)
	leaf := NewNode(m.HashFunc.Sum(nil), value)
	m.HashFunc.Reset()

	m.Leaves = append(m.Leaves, leaf)
	m.Root = buildTree(m.Leaves, m.HashFunc)
}

// UpdateLeaf updates the value of the leaf at the given index
// and recalculates the tree.
func (m *Tree) UpdateLeaf(index int, newVal []byte) error {
	if index < 0 || index >= len(m.Leaves) {
		return ErrIndexOutOfBounds
	}

	leaf := m.Leaves[index]
	m.HashFunc.Write(newVal)
	leaf.Hash = m.HashFunc.Sum(nil)
	m.HashFunc.Reset()
	leaf.Value = newVal

	m.updateParentHashes(leaf)
	return nil
}

// updateParentHashes propagates changes upwards to the root
// after a leaf has been updated.
func (m *Tree) updateParentHashes(leaf *Node) {
	current := leaf
	parent := findParent(m.Root, current)
	for parent != nil {
		if parent.Left != nil {
			m.HashFunc.Write(parent.Left.Hash)
		}
		if parent.Right != nil {
			m.HashFunc.Write(parent.Right.Hash)
		}
		parent.Hash = m.HashFunc.Sum(nil)
		m.HashFunc.Reset()

		// Move up the tree
		current = parent
		parent = findParent(m.Root, current)
	}
}

// RemoveLeaf removes a leaf at a given index
// and recalculates the tree.
func (m *Tree) RemoveLeaf(index int) error {
	if index < 0 || index >= len(m.Leaves) {
		return ErrIndexOutOfBounds
	}

	m.Leaves = slices.Delete(m.Leaves, index, index+1)

	// If there are no leaves left, the tree is now empty
	if len(m.Leaves) == 0 {
		m.Root = nil
		return nil
	}

	// Rebuild the tree with the remaining leaves
	m.Root = buildTree(m.Leaves, m.HashFunc)
	return nil
}

// Proof represents the hash chain from a leaf to the root
// to prove that a leaf is part of the tree.
type Proof struct {
	Hashes [][]byte
	Index  int
}

// GenerateProof generates an inclucion proof for a given value.
func (m *Tree) GenerateProof(value []byte) (*Proof, error) {
	return m.traverseForProof(m.Root, value, 0)
}

// traverseForProof dynamically traverses the tree to find the leaf and construct the proof
func (m *Tree) traverseForProof(node *Node, value []byte, index int) (*Proof, error) {
	if node == nil {
		return nil, ErrNoVal
	}

	if string(node.Value) == string(value) {
		return m.buildProof(node, index), nil
	}

	// Recursively search the left and right children
	if proof, err := m.traverseForProof(node.Left, value, index*2); err == nil {
		return proof, nil
	}
	return m.traverseForProof(node.Right, value, index*2+1)
}

// buildproof constructs the proof of inclucion from the leaf to the root.
func (m *Tree) buildProof(node *Node, index int) *Proof {
	var hashes [][]byte
	current := node

	for current != nil {
		siblingHash := []byte{}
		parent := findParent(m.Root, current)

		// Get sibling hash
		if parent != nil {
			if parent.Left == current {
				if parent.Right != nil {
					siblingHash = parent.Right.Hash
				}
			} else {
				if parent.Left != nil {
					siblingHash = parent.Left.Hash
				}
			}
			hashes = append(hashes, siblingHash)
		}

		// Move up the tree
		current = parent
	}

	return &Proof{
		Hashes: hashes,
		Index:  index,
	}
}

// findParent traverses the tree to find the parent of a given node.
func findParent(root, node *Node) *Node {
	if root == nil || root == node {
		return nil
	}

	// Check if either left or right child is the target node
	if root.Left == node || root.Right == node {
		return root
	}

	// Recursively check the left and right children
	if parent := findParent(root.Left, node); parent != nil {
		return parent
	}
	return findParent(root.Right, node)
}

// VerifyProof returns true if the proof is verified.
func (m *Tree) VerifyProof(proof *Proof, value []byte) bool {
	// Start by hashing the leaf value
	m.HashFunc.Write(value)
	currentHash := m.HashFunc.Sum(nil)
	m.HashFunc.Reset()

	for _, siblingHash := range proof.Hashes {
		currentHash = combineHashes(proof.Index, currentHash, siblingHash, m.HashFunc)
		// Move up to the next level, adjust the index accordingly
		proof.Index /= 2
	}

	// Compare the final calculated root hash with the actual root hash
	return string(currentHash) == string(m.Root.Hash)
}

// combineHashes combines the current and sibling hashes based on the index.
func combineHashes(index int, currentHash, siblingHash []byte, hashFunc hash.Hash) []byte {
	// Combine currentHash and siblingHash based on the index
	// The index determines if the current node is on the left or right
	if index%2 == 0 {
		// If the index is even, the current node is on the left
		hashFunc.Write(currentHash)
		hashFunc.Write(siblingHash)
	} else {
		// If the index is odd, the current node is on the right
		hashFunc.Write(siblingHash)
		hashFunc.Write(currentHash)
	}
	hash := hashFunc.Sum(nil)
	hashFunc.Reset()
	return hash
}

func (m *Tree) PrintTree() {
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
		result.WriteString(hex.EncodeToString(n.Hash) + "\n")
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
