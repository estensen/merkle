package merkle

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		leaves [][]byte
		err    error
	}{
		{
			name:   "No leaves should fail",
			leaves: [][]byte{},
			err:    ErrNoLeaves,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			tree, err := NewMerkleTree(tc.leaves, hashFunc)

			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, tree.Root, "Tree root should not be nil")
			}
		})
	}
}
