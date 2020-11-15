package solmerkle

import (
	"bytes"
)

// Byte helpers.

func sort2Bytes(i []byte, j []byte) ([]byte, []byte) {
	if lessThanBytes(i, j) {
		return i, j
	} else {
		return j, i
	}
}

func lessThanBytes(i []byte, j []byte) bool {
	switch bytes.Compare(i, j) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		return false
	}
}

func safeCopyBytes(cp []byte) []byte {
	if cp != nil {
		copied := make([]byte, len(cp))
		copy(copied, cp)
		return copied
	}
	return nil
}

func padTo(b []byte, size int) []byte {
	if len(b) > size {
		return b
	}
	return append(b, make([]byte, size-len(b))...)
}

// Math helpers.

func nextPowerOf2(n uint64) uint64 {
	var count uint64 = 0

	if isPowerOfTwo(n) {
		return n
	}

	for n != 0 {
		n >>= 1
		count += 1
	}

	return 1 << count
}

func isPowerOfTwo(n uint64) bool {
	return (n & (n - 1)) == 0
}
