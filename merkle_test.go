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
			expRoot: []byte{0x31, 0x1f, 0xe3, 0xfe, 0xed, 0x16, 0xb9, 0xcd, 0x8d, 0xf0, 0xf8, 0xb1, 0x51, 0x7b, 0xe5, 0xcb, 0x86, 0x4, 0x87, 0x7, 0xdf, 0x48, 0x89, 0xba, 0x8d, 0xc3, 0x7d, 0x4d, 0x68, 0x86, 0x6d, 0x2},
		},
		{
			name:    "Two leaves should succeed",
			leaves:  [][]byte{[]byte("yolo"), []byte("diftp")},
			expRoot: []byte{0x17, 0x29, 0xa9, 0xd9, 0x93, 0x92, 0x1f, 0x8d, 0xa5, 0x86, 0x40, 0xc8, 0x83, 0x40, 0x8d, 0xa, 0x23, 0xd8, 0x11, 0xbe, 0x44, 0xc6, 0xc3, 0x49, 0x97, 0x57, 0xdb, 0x7e, 0xed, 0x9f, 0xc7, 0x6f},
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

func TestStringifyTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		leaves [][]byte
		exp    string
	}{
		{
			name:   "Single leaf",
			leaves: [][]byte{[]byte("yolo")},
			exp:    `311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02`,
		},
		{
			name:   "Two leaves",
			leaves: [][]byte{[]byte("yolo"), []byte("diftp")},
			exp:    `1729a9d993921f8da58640c883408d0a23d811be44c6c3499757db7eed9fc76f`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			tree, err := NewMerkleTree(tc.leaves, hashFunc)
			assert.NoError(t, err)

			treeStr := tree.StringifyTree()
			assert.Equal(t, tc.exp, treeStr)
		})
	}
}
