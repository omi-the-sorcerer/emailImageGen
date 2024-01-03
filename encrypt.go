package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func generateKeys() {
	// Generar un nuevo par de claves.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Obtener la clave pública de la privada
	publicKey := &privateKey.PublicKey

	// Guardar la clave privada en un archivo.
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPem := pem.EncodeToMemory(privateKeyBlock)
	err = ioutil.WriteFile("private.pem", privateKeyPem, 0644)
	if err != nil {
		fmt.Println(err)
	}

	// Guardar la clave pública en un archivo.
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println(err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)
	err = ioutil.WriteFile("public.pem", publicKeyPem, 0644)
	if err != nil {
		fmt.Println(err)
	}
}

func getPublicKey() *rsa.PublicKey {
	// Leer la clave pública desde un archivo.
	publicKeyPem, err := ioutil.ReadFile("public.pem")
	if err != nil {
		fmt.Println(err)
	}
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		fmt.Println("failed to decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	return publicKey.(*rsa.PublicKey)
}

func main() {
	// Si no existen las claves, generarlas.
	if _, err := ioutil.ReadFile("private.pem"); err != nil {
		generateKeys()
	}

	// Mensaje a encriptar.
	message := []byte("correosuperseguro@gmail.com")

	// Obtener la clave pública.
	publicKey := getPublicKey()

	// Encriptar el mensaje.
	encryptedMessage, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		message,
		nil)
	if err != nil {
		fmt.Println(err)
	}

	// Guardar el mensaje encriptado en un archivo.
	err = ioutil.WriteFile("encrypted.txt", encryptedMessage, 0644)
	if err != nil {
		fmt.Println(err)
	}
}
