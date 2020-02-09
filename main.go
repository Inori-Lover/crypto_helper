package cryptohelper

import (
	"github.com/Inori-Lover/crypto_helper/decryption"
	"github.com/Inori-Lover/crypto_helper/encryption"
	"github.com/Inori-Lover/crypto_helper/hash"
	"github.com/Inori-Lover/crypto_helper/helper"
	"github.com/Inori-Lover/crypto_helper/pwh"
)

// 为什么创建这个库
// 1. 原生的加密函数错误处理导致导致不能实现行内赋值
// 2. IV的选取策略多种多样，并非所有人都知道IV的目的是什么
// 3. 并没有人简单知道自己应该选什么类型的加密、hash等

// AddErrorCB 添加错误监听callback
func AddErrorCB(cb func(err error)) {
	helper.AddErrorCB(cb)
}

// Encryption 推荐加密方法
func Encryption(plaintext []byte, key [32]byte) []byte {
	return encryption.AesCtr256(plaintext, key)
}

// Decryption 推荐解密方法
func Decryption(plaintext []byte, key [32]byte) []byte {
	return decryption.AesCtr256(plaintext, key)
}

// Hash 推荐Hash
func Hash(plaintext []byte) (hashBytes []byte) {
	return hash.Blake2(plaintext)
}

// PasswordHash 推荐密码加密(Hash)
// 注意: 这**不**输出标准的 Argon2 序列化方案, 免除大堆序列化解析流程
// 需要与其他库无痛交互的话建议使用`https://github.com/raja/argon2pw`代替
func PasswordHash(plaintext []byte) (hashBytes []byte) {
	return pwh.Argon2(plaintext)
}

// PasswordHashCheck 推荐密码解密(Hash校验)
// 注意: 这**不**接受标准的 Argon2 序列化方案, 免除大堆序列化解析流程
// 需要与其他库无痛交互的话建议使用`https://github.com/raja/argon2pw`代替
func PasswordHashCheck(password []byte, hash []byte) bool {
	return pwh.Argon2Check(password, hash)
}
