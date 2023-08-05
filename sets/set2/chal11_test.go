package set2_test

import (
	"cryptopals/pkg/aes"
	"os"
	"testing"
)

func TestChal11(t *testing.T) {
	// read file
	pt, err := os.ReadFile("../../res/set2/11.txt")
	if err != nil {
		t.Error(err)
		return
	}

	const numTries = 20
	for i := 0; i < numTries; i++ {
		// encrypts the plaintext with ECB or CBC. 1/2 prob each
		ct, useECB, err := aes.EncryptionOracle(pt)
		if err != nil {
			t.Error(err)
			return
		}
		// returns true if ciphertext is detected to be encrypted with ECB
		detectedECB := aes.DetectionOracle(ct)

		// TODO
		if useECB != detectedECB {
			t.Log("USED:", useECB, "\tDETECTED:", detectedECB)
			t.Log("CT:", ct, "\tECB:", useECB)
			t.Fail()
		}
	}
}
