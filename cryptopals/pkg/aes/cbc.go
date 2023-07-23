package aes

import (
	"crypto/aes"
	"cryptopals/internal/constants"
	"cryptopals/pkg/pkcs7"
	"cryptopals/pkg/xor"
)

// AES encryption with CBC (Cipher Block Chaining)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func CBCEncrypt(pt, iv, key []byte, size int) ([]byte, int, error) {
	// create block cipher
	if len(key) != size {
		return nil, 0, constants.ErrWrongKeySize
	}
	if len(iv) != size {
		return nil, 0, constants.ErrWrongIVSize
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	if len(pt)%size != 0 {
		return nil, 0, constants.ErrLenMismatch
	}

	// make sure input length is multiple of block length

	// padding := uint8(size - (len(pt) % size))
	// if padding == 0 {
	// 	padding = size
	// }
	// for i := padding; i > 0; i-- {
	// 	pt = append(pt, padding)
	// }
	pt = pkcs7.Pad(pt, size)

	// encrypt
	ct := make([]byte, len(pt))
	prev := make([]byte, size)
	copy(prev, iv)
	for be := size; be <= len(ct); be += size {
		bs := be - size
		// xor with prev
		xor, err := xor.XOR(pt[bs:be], prev)
		if err != nil {
			return nil, 0, err
		}
		// encrypt
		cipher.Encrypt(ct[bs:be], xor)
		// update prev
		copy(prev, ct[bs:be])

	}

	return ct, 0, nil
	// return ct[:len(pt)-int(padding)], int(padding), nil
}

// AES decryption with CBC (Cipher Block Chaining)
//
// Size must be 16, 24 or 32 for AES-128, AES-192 or AES-256 respectively.
func CBCDecrypt(ct, iv, key []byte, size int) ([]byte, int, error) {
	// create block cipher
	if len(key) != size {
		return nil, 0, constants.ErrWrongKeySize
	}
	if len(iv) != size {
		return nil, 0, constants.ErrWrongIVSize
	}
	if len(ct)%size != 0 {
		return nil, 0, constants.ErrLenMismatch
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}

	// make sure input length is multiple of block length
	// padding := size - (len(ct) % size)
	// if padding > 0 {
	// 	pad := make([]byte, padding)
	// 	ct = append(ct, pad...)
	// }
	ct = pkcs7.Pad(ct, size)

	// decrypt
	pt := make([]byte, len(ct))
	prev := make([]byte, size)
	copy(prev, iv)
	for be := size; be <= len(ct); be += size {
		bs := be - size
		// decrypt
		cipher.Decrypt(pt[bs:be], ct[bs:be])
		// xor with prev
		xor, err := xor.XOR(pt[bs:be], prev)
		if err != nil {
			return nil, 0, err
		}
		copy(pt[bs:be], xor)
		// update prev
		copy(prev, ct[bs:be])
	}

	// return pt[:len(ct)-padding], padding, nil
	return pt, 0, nil
}
