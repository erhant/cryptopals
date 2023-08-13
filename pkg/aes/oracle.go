package aes

import (
	"cryptopals/internal/common"
)

// Just like OracleEncrypt function, with the key is created randomly
// on each function call.
func OracleEncryptRandom(pt []byte, size int) ([]byte, bool, error) {
	key, err := common.RandBytes(size)
	if err != nil {
		return nil, false, err
	}

	return OracleEncrypt(pt, key, size)
}

// Appends & preprends some stuff to the plaintext,
// and then encrypts the entire thing with the given key.
//
// It will flip a coin, and will encrypt based on ECB or CBC based on the result.
//
// Returns the ciphertext and a bool where (true: ECB) and (false: CBC).
func OracleEncrypt(pt, key []byte, size int) ([]byte, bool, error) {
	if prependBytes, err := common.RandBytes(common.RandInteger(5, 10)); err != nil {
		return nil, false, err
	} else {
		pt = append(prependBytes, pt...)
	}

	if appendBytes, err := common.RandBytes(common.RandInteger(5, 10)); err != nil {
		return nil, false, err
	} else {
		pt = append(pt, appendBytes...)
	}

	if common.RandBool() {
		// encrypt with ECB
		ct, err := ECBEncrypt(pt, key, 16)
		if err != nil {
			return nil, true, err
		}

		return ct, true, err
	} else {
		// generate random iv
		iv, err := common.RandBytes(size)
		if err != nil {
			return nil, false, err
		}

		// encrypt with CBC
		ct, err := CBCEncrypt(pt, iv, key, 16)
		if err != nil {
			return nil, false, err
		}

		return ct, false, nil
	}
}

// Given a ciphertext, this function returns a bool meaning:
//
// - true: ciphertext was encrypted using ECB.
//
// - false: ciphertext was encrypted using CBC.
func OracleDetect(ct []byte, size int) bool {
	// similar to Challenge 8, where we detected from a set of ciphertexts
	// which one was encrypted using ECB, we check for repeating blocks again
	s := common.NumRepeatingBlocks(ct, size)

	return s > 0
}
