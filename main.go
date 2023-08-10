package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize  = 16
	IterCount = 4096

	ScramSHA256Name = "SCRAM-SHA-256"
	clientKeyName   = "Client Key"
	serverKeyName   = "Server Key"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <password>\n", os.Args[0])
	}

	pass, err := ScramSHA256Auth(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pass)
}

func ScramSHA256Auth(password string) (string, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	saltedPassword := pbkdf2.Key([]byte(password), salt, IterCount, sha256.Size, sha256.New)

	h := hmac.New(sha256.New, saltedPassword)
	h.Write([]byte(clientKeyName))
	clientKey := h.Sum(nil)
	storedKey := sha256.Sum256(clientKey)

	h.Reset()
	h.Write([]byte(serverKeyName))
	serverKey := h.Sum(nil)

	enc := base64.StdEncoding.EncodeToString

	return fmt.Sprintf("%s$%d:%s$%s:%s",
		ScramSHA256Name,
		IterCount,
		enc(salt),
		enc(storedKey[:]),
		enc(serverKey),
	), nil
}
