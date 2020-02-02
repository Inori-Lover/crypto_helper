package pwh

// Hash 默认密码Hash
func Hash(plaintext []byte) []byte {
	return Argon2(plaintext)
}

// Check 默认密码Hash校验
func Check(password []byte, hash []byte) bool {
	return Argon2Check(password, hash)
}
