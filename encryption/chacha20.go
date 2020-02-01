package encryption

import (
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"crypto_helper/hash"
	"crypto_helper/helper"
)

func xChacha20(plaintext []byte, key []byte) []byte {
	iv := hash.BLAKE_2(plaintext)[:chacha20.NonceSizeX]
	mode, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	ciphertext := make([]byte, len(plaintext))
	mode.XORKeyStream(ciphertext, plaintext)

	return append(iv, ciphertext...)
}
func XChacha20(plaintext []byte, key [chacha20.KeySize]byte) []byte {
	return xChacha20(plaintext, key[:])
}

func xChacha20poly1305(plaintext []byte, key []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	iv := hash.BLAKE_2(plaintext)[:chacha20poly1305.NonceSizeX]

	ciphertext := aead.Seal(nil, iv, plaintext, nil)

	return append(iv, ciphertext...)
}
func XChacha20poly1305(plaintext []byte, key [chacha20poly1305.KeySize]byte) []byte {
	return xChacha20poly1305(plaintext, key[:])
}
