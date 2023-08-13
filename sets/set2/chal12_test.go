package set2_test

import (
	"bytes"
	"cryptopals/internal/common"
	"cryptopals/pkg/aes"
	"encoding/base64"
	"os"
	"testing"
)

// TODO:
// proof of concept done, do the same with oracle now

func TestChal12(t *testing.T) {
	size := 16

	// key to be used for encryption
	// (assuming that we dont actually see it)
	key, err := common.RandBytes(size)
	if err != nil {
		t.Fatal(err)
	}

	// remember, do not decode & read this string yourself
	suffix64, err := os.ReadFile("../../res/set2/12.txt")
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := base64.StdEncoding.DecodeString(string(suffix64))
	if err != nil {
		t.Fatal(err)
	}

	// TODO: step 1 & step 2
	// skipping those steps for the time being...
	// so, assuming that we use ECB with size 16

	// we will consume the suffix byte-by-byte
	decipheredSuffix := make([]byte, len(suffix))
	for i := 0; i < len(suffix); i++ {
		prefix := bytes.Repeat([]byte("A"), size-1)

		// original plaintext & ciphertext for this byte
		pt := append(prefix, suffix[i])
		ct, err := aes.ECBEncrypt(pt, key, size)
		if err != nil {
			t.Fatal(err)
		}

		// create each possible plaintext for that last byte
		for b := 0; b < 256; b++ {
			cand_pt := append(prefix, byte(b))
			cand_ct, err := aes.ECBEncrypt(cand_pt, key, size)
			if err != nil {
				t.Fatal(err)
			}

			// ciphertexts match!
			if bytes.Equal(ct, cand_ct) {
				decipheredSuffix[i] = byte(b)
				break
			}
		}
	}

	if !bytes.Equal(decipheredSuffix, suffix) {
		t.Fatal("Results not matching.")
	}
}
