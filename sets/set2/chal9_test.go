package set2_test

import (
	"bytes"
	"cryptopals/internal/constants"
	"cryptopals/pkg/pkcs7"
	"testing"
)

func TestChal9(t *testing.T) {
	buf := []byte("YELLOW SUBMARINE")
	paddedBuf := pkcs7.Pad(buf, 20)            // pad to 20 bytes
	unpaddedBuf, err := pkcs7.Unpad(paddedBuf) // unpad
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, unpaddedBuf) {
		t.Fatal(constants.ErrWrongResult)
		return
	}
}
