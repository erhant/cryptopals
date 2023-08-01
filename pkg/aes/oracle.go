package aes

import (
	"cryptopals/internal/common"
	"fmt"
)

// This function creates a random 128-bit key,
// appends & preprends some stuff to the plaintext
// and then encrypts the entire thing. Half of the time,
// it will use ECB mode, otherwise CBC.
func EncryptionOracle(pt []byte) ([]byte, bool, error) {
	const size = 16 // TODO: take parameter
	// create random 16-byte key
	key, err := common.RandBytes(size)
	if err != nil {
		return nil, false, err
	}

	// prepend
	if prependBytes, err := common.RandBytes(common.RandInteger(5, 10)); err != nil {
		return nil, false, err
	} else {
		pt = append(prependBytes, pt...)
	}

	// append
	if appendBytes, err := common.RandBytes(common.RandInteger(5, 10)); err != nil {
		return nil, false, err
	} else {
		pt = append(pt, appendBytes...)
	}

	// encrypt
	var ct []byte
	useECB := common.RandBool()
	if useECB {
		// encrypt with ECB
		ct, err = ECBEncrypt(pt, key, 16)
		if err != nil {
			return nil, false, err
		}
	} else {
		// generate random iv
		iv, err := common.RandBytes(size)
		if err != nil {
			return nil, false, err
		}
		// encrypt with CBC
		ct, err = CBCEncrypt(pt, iv, key, 16)
		if err != nil {
			return nil, false, err
		}
	}

	return ct, useECB, nil
}

// Given a ciphertext, this function returns true if
// the given ciphertext was encrypted using ECB. Returning
// false means that ciphertext was encrypted using CBC.
func DetectionOracle(ct []byte) bool {
	// TODO: take parameter
	const size = 16
	// similar to previous challenge, try to check for repeating blocks
	s := common.RepeatingBlocks(ct, size)
	fmt.Println("Repeating:", s)
	return s > 0
}
