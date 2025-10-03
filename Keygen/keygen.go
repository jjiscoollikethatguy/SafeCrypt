package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func main() {

	_, err := makePrivateKey()
	if err != nil {
		panic(err)

	}
	privatekeyFile, err := os.ReadFile("private_key.pem")
	if err != nil {
		panic(err)

	}

	block, _ := pem.Decode(privatekeyFile)
	if block == nil {
		fmt.Println("error with privatekey file!")
		os.Exit(1)

	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)

	}

	err = makePublicKey(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("Saved private and public key to current directory")

}

func makePrivateKey() (bool, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, err
	}

	// Encode the private key into PEM format
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	// Write the private key to a file
	err = os.WriteFile(
		"private_key.pem",
		privateKeyPEM,
		0644,
	)
	if err != nil {
		return false, err
	}

	return true, nil
}

func makePublicKey(privateKey *rsa.PrivateKey) error {

	publicKey := &privateKey.PublicKey
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		},
	)

	publicKeyString := string(publicKeyPEM)

	err := os.WriteFile(
		"public_key.pem",
		[]byte(publicKeyString),
		0644,
	)
	if err != nil {
		return err
	}

	return nil
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := io.ReadFull(rand.Reader, key)

	if err != nil {
		return nil, err
	}

	return key, nil
}

func EncryptWithPublicKey(plainText []byte, key *rsa.PublicKey) ([]byte, error) {

	cipherText, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		key,
		plainText,
	)
	if err != nil {
		return nil, err
	}
	return cipherText, nil

}
