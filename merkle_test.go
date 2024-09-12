package merkle

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		leaves  [][]byte
		expRoot []byte
		err     error
	}{
		{
			name:   "No leaves should fail",
			leaves: [][]byte{},
			err:    ErrNoLeaves,
		},
		{
			name:    "One leaf should succeed",
			leaves:  [][]byte{[]byte("yolo")},
			expRoot: []byte{0x79, 0x6f, 0x6c, 0x6f, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
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
				assert.Equal(t, tc.expRoot, tree.Root, "Tree root should not be nil")
			}
		})
	}
}
