package encryption

// Default is AES_CTR_256
func Default(plaintext []byte, key [32]byte) []byte {
	return AesCtr256(plaintext, key)
}
