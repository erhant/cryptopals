package aes

import (
	"crypto/aes"
	"cryptopals/internal/constants"
	"cryptopals/pkg/xor"
)

// AES encryption with CBC (Cipher Block Chaining)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func CBCEncrypt(pt, iv, key []byte, size int) ([]byte, error) {
	if len(key) != size {
		return nil, constants.ErrWrongKeySize
	}
	if len(iv) != size {
		return nil, constants.ErrWrongIVSize
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(pt))
	prev := make([]byte, size)
	copy(prev, iv)
	for be := size; be <= len(ct); be += size {
		bs := be - size

		// xor with prev
		xor, err := xor.XOR(pt[bs:be], prev)
		if err != nil {
			return nil, err
		}

		cipher.Encrypt(ct[bs:be], xor)
		copy(prev, ct[bs:be])
	}

	return ct, nil
}

// AES decryption with CBC (Cipher Block Chaining)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func CBCDecrypt(ct, iv, key []byte, size int) ([]byte, error) {
	if len(key) != size {
		return nil, constants.ErrWrongKeySize
	}
	if len(iv) != size {
		return nil, constants.ErrWrongIVSize
	}
	if len(ct)%size != 0 {
		return nil, constants.ErrLenMismatch
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// decrypt
	pt := make([]byte, len(ct))
	prev := make([]byte, size)
	copy(prev, iv)
	for be := size; be <= len(ct); be += size {
		bs := be - size

		cipher.Decrypt(pt[bs:be], ct[bs:be])

		// xor with prev
		xor, err := xor.XOR(pt[bs:be], prev)
		if err != nil {
			return nil, err
		}

		copy(pt[bs:be], xor)
		copy(prev, ct[bs:be])
	}

	return pt, nil
}
