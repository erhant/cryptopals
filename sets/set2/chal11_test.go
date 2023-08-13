package set2_test

import (
	"cryptopals/pkg/aes"
	"os"
	"testing"
)

func TestChal11(t *testing.T) {
	size := 16

	pt, err := os.ReadFile("../../res/set2/11.txt")
	if err != nil {
		t.Fatal(err)
	}

	// try this many times
	for i := 0; i < 30; i++ {
		// encrypts the plaintext with ECB or CBC
		// returns the choice for testing purposes
		ct, useECB, err := aes.OracleEncryptRandom(pt, size)
		if err != nil {
			t.Fatal(err)
		}

		// returns true if ciphertext is detected to be encrypted with ECB
		detectedECB := aes.OracleDetect(ct, size)

		if useECB != detectedECB {
			t.Fatal("USED:", useECB, "\tDETECTED:", detectedECB)
		}
	}
}
