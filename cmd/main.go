package main

import (
	"GoCryptoCipher/internal/cipher"
	"fmt"
	"log"
)

const key = "c7254012elefbc6hbc51e22ff58d190d"

func main() {
	err := encrypt("Hola Mundo", key)
	if err != nil {
		log.Println(err.Error())
	}

	err = decrypt("bQ5tLxQOzyU7JbjNQJfF1nTFklNMx1yhj5Y4p1MAmB8=", key)

	if err != nil {
		log.Println(err.Error())
	}

}

func encrypt(textToEncrypt string, key string) error {
	fmt.Println("=================== ENCRYPT ===================")

	aes256 := cipher.NewAesCBC()
	resp, err := aes256.Crypt(&cipher.Request{
		Value:     textToEncrypt,
		SecretKey: key,
	})

	if err != nil {
		return err
	}

	fmt.Println("Text to encrypt: " + textToEncrypt)
	fmt.Println("Text encrypted: " + resp.Value)
	fmt.Println()

	return nil
}

func decrypt(textToDecrypt string, key string) error {
	fmt.Println("=================== DECRYPT ===================")

	aes256 := cipher.NewAesCBC()
	resp, err := aes256.Decrypt(&cipher.Request{
		Value:     textToDecrypt,
		SecretKey: key,
	})

	if err != nil {
		return err
	}

	fmt.Println("Text to decrypt: " + textToDecrypt)
	fmt.Println("Text decrypted: " + resp.Value)

	return nil
}
