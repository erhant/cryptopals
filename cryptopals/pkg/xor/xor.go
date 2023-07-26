package xor

import "cryptopals/internal/constants"

// Simple XOR. Returns a new array.
func XOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, constants.ErrLenMismatch
	}

	ans := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		ans[i] = a[i] ^ b[i]
	}
	return ans, nil
}

// Simple XOR. Writes the result to `dest`.
func XORDest(dest, a, b []byte) error {
	if len(a) != len(b) {
		return constants.ErrLenMismatch
	}
	if len(a) != len(dest) {
		return constants.ErrLenMismatch
	}

	for i := 0; i < len(a); i++ {
		dest[i] = a[i] ^ b[i]
	}
	return nil
}
