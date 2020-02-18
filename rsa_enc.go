package main

import (
	"math/big"
	"crypto/rand"
	"fmt"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"crypto/aes"
	"io"
	"os"
	"io/ioutil"
)

var e, _ = new(big.Int).SetString("3",10)
var p big.Int
var q big.Int
var n big.Int
var d big.Int
var aes_key []byte
var fileContentSizeInBytes int
var blockGlobal cipher.Block
var ivGlobal []byte

func MakePublicPrivateRsaKeys(k int) (big.Int, big.Int){
	p,q,n,d = KeyGen(k)

	return n,d
}

func KeyGen(k int) (big.Int, big.Int, big.Int, big.Int){ // outputs the modulus n
	pLength :=  k/2// Might be insecure since we will have that |p|=|q|
	qLength := k-pLength // Makes sure that multiple of pq is k bits long
	var nResult big.Int
	var totient big.Int
	var d1 big.Int

	p1 := GenerateCoprime(e,pLength) // We choose the first prime
	q1 := GenerateCoprime(e,qLength) // We choose the second prime
	one,_ := new(big.Int).SetString("1", 10)
	totient.Mul(new(big.Int).Sub(p1,one),new(big.Int).Sub(q1,one))
	(&d1).ModInverse(e,&totient)

	return *p1, *q1, *nResult.Mul(p1,q1), d1 // Should return a k-bit number which is a multiple of primes p and q
}

func Encrypt(message big.Int, publicKey big.Int) big.Int{
	c := new(big.Int).Exp(&message,e,&publicKey)
	return *c
}

func Decrypt(c big.Int) big.Int{
	m := new(big.Int).Exp(&c,&d,&n)
	return *m
}

func GenerateCoprime(prime *big.Int, length int) *big.Int{
	result,_ := rand.Prime(rand.Reader, length)

	for gcd(prime,result.Sub(result,big.NewInt(1))).Cmp(big.NewInt(1)) != 0 { // GCD(prime, p-1) == 1 ?
		result, _ = rand.Prime(rand.Reader, length) // If GCD is not 1, try again
	}

	result.Add(result, big.NewInt(1))

	return result
}

func gcd(a, b *big.Int) *big.Int {
	var gcd big.Int
	return gcd.GCD(nil,nil,a,b)
}

func EncryptToFile(filename string) {
	aes_key, _ = hex.DecodeString("6368616e676520746869732070617373") // Just a random key, converted to byte array
	keyToEncrypt := d.Bytes() // Getting bytes of the secret key

	fmt.Println("Key to encrypt is ", keyToEncrypt)

	block, err := aes.NewCipher(aes_key)
	blockGlobal = block
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(keyToEncrypt))
	fileContentSizeInBytes = len(ciphertext)
	iv := ciphertext[:aes.BlockSize]
	ivGlobal = iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil { // Generate a random IV
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], keyToEncrypt)

	file, err := os.Create(filename)
	if err != nil {panic(err)}
	defer file.Close()
	file.Write(ciphertext)

	fmt.Println("Written encrypted key to file: ", ciphertext)
}

func DecryptFromFile(filename string) big.Int{
	block, err := aes.NewCipher(aes_key)
	encryptedKey, err := ioutil.ReadFile(filename)
	iv := encryptedKey[:aes.BlockSize]
	if err != nil {panic(err)}

	fmt.Println("Trying to decrypt from file ", encryptedKey)

	// Da AES-CTR er symmetrisk, laver vi encrypt og decrypt på samme måde
	decryptedKey := make([]byte, len(d.Bytes()))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decryptedKey, encryptedKey[aes.BlockSize:])

	fmt.Println("Decrypted key is ", decryptedKey)

	return *new(big.Int).SetBytes(decryptedKey)
}

func Sign(message big.Int) (big.Int) {
	hash := Sha256Hash(message.Bytes());
	hashAsBigInt := new(big.Int).SetBytes(hash[:]);
	signedHash := Decrypt(*hashAsBigInt); // We are actually not decrypting, but we use the private key to sign the hash

	return signedHash;
}

func Sha256Hash(message []byte) [32]byte{
	return sha256.Sum256(message);
}
