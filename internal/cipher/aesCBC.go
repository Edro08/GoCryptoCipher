package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	errorDescription = "Error description: "
)

type AesCBC struct {
}

func NewAesCBC() *AesCBC {
	return &AesCBC{}
}

// Crypt AES encryption
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// SecretKey and text to cipher ere plain text.
// Return response with base64 string
func (cbc *AesCBC) Crypt(request *Request) (*Response, error) {

	keyLen := len(request.SecretKey)
	if !(keyLen == 16 || keyLen == 24 || keyLen == 32) {
		return nil, fmt.Errorf("%s invalid aes cbc secret key", errorDescription)
	}

	key := []byte(request.SecretKey)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding
	plaintext := pKCS5Padding([]byte(request.Value), aes.BlockSize)

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%s aes cbc plaintext is not a multiple of the block size", errorDescription)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%s aes cbc error creating aes instance", errorDescription)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	// static initialization vector to produce the same result
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("%s aes cbc error creating initialization vector", errorDescription)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return &Response{
		Value: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// Decrypt AES encryption
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// SecretKey to decrypt is plain text.
// Text to decrypt is base64.
// return response with plain text.
func (cbc *AesCBC) Decrypt(request *Request) (*Response, error) {

	keyLen := len(request.SecretKey)
	if !(keyLen == 16 || keyLen == 24 || keyLen == 32) {
		return nil, fmt.Errorf("%s invalid aes cbc secret key", errorDescription)
	}

	key := []byte(request.SecretKey)
	ciphertext, err := base64.StdEncoding.DecodeString(request.Value)

	if err != nil {
		return nil, fmt.Errorf("%s aes cbc decryption error base 64 decoding: %s", errorDescription, err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%s error aes cbc creating instance: %s", errorDescription, err.Error())
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("%s aes cbc ciphertext to decrypt too short", errorDescription)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	// static initialization vector
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%s aes cbc ciphertext to decrypt is not a multiple of the block size", errorDescription)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point.
	ciphertext, err = pKCS5UnPadding(ciphertext)
	if err != nil {
		return nil, err
	}

	return &Response{
		Value: string(ciphertext),
	}, nil
}

// For crypto algorithms that operate on blocks of data such as those
// in cipher-block chaining (CBC) mode. We have to make sure that the data passed in
// is a multiple of our block size. In reality, most of the time our data won't be
// and we need to add padding to the end of our plaintext data to make it a multiple.
// Padding process is to add extra bytes to the end of the data.
// The rule of thumb is that, padding and un-padding
// take place outside of encryption and decryption.
func pKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// Un-pad, is the process of removing the last byte and check to see
// if the un-padded result make sense.
// The rule of thumb is that, padding and un-padding
// take place outside of encryption and decryption.
func pKCS5UnPadding(src []byte) ([]byte, error) {

	var err error

	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Recover from panic: ")
			fmt.Println(err)
			err = fmt.Errorf("%s recovering from panic error, invalid key", errorDescription)
		}
	}()

	length := len(src)
	padding := int(src[length-1])
	return src[:(length - padding)], err
}
