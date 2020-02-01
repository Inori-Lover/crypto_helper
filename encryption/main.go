package encryption

// Default is AES_CTR_256
func Default(plaintext []byte, key [32]byte) []byte {
	return AES_CTR_256(plaintext, key)
}
