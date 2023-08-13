package set2_test

import (
	"cryptopals/internal/constants"
	"cryptopals/pkg/pkcs7"
	"testing"
)

func TestChal15(t *testing.T) {
	t.FailNow() // TODO

	// valid padding, expect no errors
	if _, err := pkcs7.Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04")); err != nil {
		t.Fatal(err)
	}

	// invalid padding, expect error
	if _, err := pkcs7.Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05")); err == nil {
		t.Fatal(constants.ErrExpectedError)
	}

	// invalid padding, expect error
	if _, err := pkcs7.Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04")); err == nil {
		t.Fatal(constants.ErrExpectedError)
	}
}
