package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fogleman/gg"
	"io/ioutil"
)

func getPrivateKey() *rsa.PrivateKey {
	// Leer la clave privada desde un archivo.
	privateKeyPem, err := ioutil.ReadFile("private.pem")
	if err != nil {
		fmt.Println(err)
	}
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		fmt.Println("failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	return privateKey
}

func main() {
	privateKey := getPrivateKey()

	// Leer el mensaje encriptado desde un archivo.
	encryptedMessage, err := ioutil.ReadFile("encrypted.txt")
	if err != nil {
		fmt.Println(err)
	}

	// Desencriptar el mensaje.
	decryptedMessage, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedMessage,
		nil)
	if err != nil {
		fmt.Println(err)
	}

	const P = 1
	// Crear un contexto con un tamaño arbitrario
	dc := gg.NewContext(1000, 1000)

	// Configurar las propiedades del texto
	dc.SetRGB(0, 0, 0)

	// Medir el tamaño del texto
	w, h := dc.MeasureString(string(decryptedMessage))

	// Crear un nuevo contexto con el tamaño adecuado
	dc = gg.NewContext(int(w+2*P), int(h+2*P))

	// Configurar las propiedades del texto de nuevo
	dc.SetRGB(1, 1, 1)
	dc.Clear()
	dc.SetRGB(0, 0, 0)

	// Dibujar el texto en el centro del lienzo
	dc.DrawStringAnchored(string(decryptedMessage), w/2+P, h/2+P, 0.5, 0.5)

	// Guardar la imagen
	dc.SavePNG("out.png")
}
