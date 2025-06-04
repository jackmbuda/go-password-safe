package main

import (
	"os"
)

const storeFile = "passwords.safe"

// PasswordStore represents the structure of your password data.
type PasswordStore struct {
	Passwords map[string]string `json:"passwords"`
}

// save saves the encrypted data and salt to the store file.
func save(encryptedData, salt []byte) error {
	file, err := os.Create(storeFile)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(salt); err != nil {
		return err
	}
	if _, err := file.Write(encryptedData); err != nil {
		return err
	}
	return nil
}

// load reads the salt and encrypted data from the store file.
func load() ([]byte, []byte, error) {
	data, err := os.ReadFile(storeFile)
	if err != nil {
		return nil, nil, err
	}

	salt := data[:16]
	encrypted := data[16:]
	return encrypted, salt, nil
}
