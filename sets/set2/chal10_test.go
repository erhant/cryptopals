package set2_test

import (
	"bytes"
	"cryptopals/internal/constants"
	"cryptopals/pkg/aes"
	"encoding/base64"
	"os"
	"testing"
)

func TestCBC(t *testing.T) {
	size := 16

	key := []byte("YELLOW SUBMARINE") // 16-byte key
	iv := make([]byte, size)          // 16-byte all zeros
	pt := []byte("BLUE EYED FISHES")  // 16-byte plaintext

	ct, err := aes.CBCEncrypt(pt, iv, key, size)
	if err != nil {
		t.Fatal(err)
		return
	}

	ptTest, err := aes.CBCDecrypt(ct, iv, key, size)
	if err != nil {
		t.Fatal(err)
		return
	}

	t.Log(string(ptTest))
	if !bytes.Equal(pt, ptTest) {
		t.Fatal(constants.ErrWrongResult)
	}
}

func TestChal10(t *testing.T) {
	// read file (base64 encoded)
	fileb64, err := os.ReadFile("../../res/set2/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	// decode
	key := []byte("YELLOW SUBMARINE")
	ct := make([]byte, base64.StdEncoding.DecodedLen(len(fileb64)))
	base64.StdEncoding.Decode(ct, fileb64)
	iv := make([]byte, 16) // 128-bit all zeros

	// decrypt
	pt, err := aes.CBCDecrypt(ct, iv, key, 16)
	if err != nil {
		t.Fatal(err)
	}

	expectedPrefix := "I'm back and I'm ringin' the bell"
	if string(pt)[:len(expectedPrefix)] != expectedPrefix {
		t.Fatal(constants.ErrWrongResult)
	}

	t.Log(string(pt))

}
