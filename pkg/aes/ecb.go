package aes

import (
	"crypto/aes"
	"cryptopals/internal/constants"
	"log"
)

// AES encryption with ECB (Electronic Code Book)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func ECBEncrypt(pt, key []byte, size int) ([]byte, error) {
	if len(key) != size {
		return nil, constants.ErrWrongKeySize
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// check plaintext size
	if len(pt)&size != 0 {
		log.Printf("Plaintext length %d not a multiple of 128", len(pt))
	}

	// encrypt
	ct := make([]byte, len(pt))
	for i := 0; i < len(pt)/size; i++ {
		bs, be := i*size, (i+1)*size
		cipher.Encrypt(ct[bs:be], pt[bs:be])
	}

	return ct, nil
}

// AES decryption with ECB (Electronic Code Book)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func ECBDecrypt(ct, key []byte, size int) ([]byte, error) {
	if len(key) != size {
		return nil, constants.ErrWrongKeySize
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// decrypt
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct)/size; i++ {
		bs, be := i*size, (i+1)*size
		cipher.Decrypt(pt[bs:be], ct[bs:be])
	}

	return pt, nil
}
