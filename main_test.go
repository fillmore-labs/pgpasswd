package main_test

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"testing"

	main "github.com/fillmore-labs/pgpasswd"
)

const (
	expr = `^([^$:]+)\$([0-9]+):([^$:]+)\$([^$:]+):([^$:]+)$`
)

const (
	namePos int = iota + 1
	iterPos
	saltPos
	storedKeyPos
	serverKeyPos
)

func TestComputeAuth(t *testing.T) {
	r := regexp.MustCompile(expr)
	dec := base64.StdEncoding.DecodeString

	auth, err := main.ScramSHA256Auth("password")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	m := r.FindStringSubmatch(auth)
	if len(m) != 6 {
		t.Fatal("Wrong format")
	}

	if m[namePos] != main.ScramSHA256Name {
		t.Error("Wrong identifier")
	}

	if iter, err := strconv.Atoi(m[iterPos]); err != nil || iter != main.IterCount {
		t.Error("Unexpected iteration count")
	}

	if salt, err := dec(m[saltPos]); err != nil || len(salt) != 16 {
		t.Error("Unexpected salt")
	}

	if storedKey, err := dec(m[storedKeyPos]); err != nil || len(storedKey) != sha256.Size {
		t.Error("Unexpected stored key")
	}

	if serverKey, err := dec(m[serverKeyPos]); err != nil || len(serverKey) != sha256.Size {
		t.Error("Unexpected server key")
	}
}
