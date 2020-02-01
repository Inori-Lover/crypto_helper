package passwordHash

func Hash(plaintext []byte) []byte {
	return Argon2(plaintext)
}

func Check(password []byte, hash []byte) bool {
	return Argon2Check(password, hash)
}
