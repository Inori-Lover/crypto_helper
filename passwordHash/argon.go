package passwordHash

import (
	"bytes"
	"crypto/rand"
	"crypto_helper/helper"

	argon "golang.org/x/crypto/argon2"
)

const (
	defaultMemory      = 64 * 1024
	defaultParallelism = 4
	defaultOutputSize  = 32
	defaultSaltSize    = 8
	defaultTime        = 1
)

func argon2(plaintext []byte) []byte {
	salt := make([]byte, defaultSaltSize)

	if _, err := rand.Read(salt); err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	ciphertext := argon.IDKey(plaintext,
		salt,
		defaultTime,
		defaultMemory,
		defaultParallelism,
		defaultOutputSize,
	)

	return append(salt, ciphertext...)
}
func Argon2(plaintext []byte) []byte {
	return argon2(plaintext)
}

func argon2Check(plaintext []byte, ciphertext []byte) bool {
	if len(ciphertext) != defaultOutputSize+defaultSaltSize {
		return false
	}
	salt := ciphertext[:defaultSaltSize]
	ciphertext = ciphertext[defaultSaltSize:]

	return bytes.Equal(
		ciphertext,
		argon.IDKey(plaintext,
			salt,
			defaultTime,
			defaultMemory,
			defaultParallelism,
			defaultOutputSize,
		),
	)
}
func Argon2Check(password []byte, hash []byte) bool {
	return argon2Check(password, hash)
}
