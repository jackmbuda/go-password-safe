package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

func main() {
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	addService := addCmd.String("service", "", "The service to add a password for.")
	addPassword := addCmd.String("password", "", "The password for the service.")

	getCmd := flag.NewFlagSet("get", flag.ExitOnError)
	getService := getCmd.String("service", "", "The service to get the password for.")

	if len(os.Args) < 2 {
		fmt.Println("expected 'add' or 'get' subcommands")
		os.Exit(1)
	}

	fmt.Print("Enter master password: ")
	masterPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error reading master password:", err)
		os.Exit(1)
	}
	fmt.Println()

	switch os.Args[1] {
	case "add":
		addCmd.Parse(os.Args[2:])
		if *addService == "" || *addPassword == "" {
			fmt.Println("service and password are required for add command")
			addCmd.PrintDefaults()
			os.Exit(1)
		}
		handleAdd(string(masterPassword), *addService, *addPassword)
	case "get":
		getCmd.Parse(os.Args[2:])
		if *getService == "" {
			fmt.Println("service is required for get command")
			getCmd.PrintDefaults()
			os.Exit(1)
		}
		handleGet(string(masterPassword), *getService)
	default:
		fmt.Println("expected 'add' or 'get' subcommands")
		os.Exit(1)
	}
}

func handleAdd(masterPassword, service, password string) {
	var passwords PasswordStore
	encryptedData, salt, err := load()
	if err == nil {
		key, _ := deriveKey([]byte(masterPassword), salt)
		decryptedData, _ := decrypt(encryptedData, key)
		json.Unmarshal(decryptedData, &passwords)
	} else {
		passwords.Passwords = make(map[string]string)
		salt, _ = newSalt()
	}

	passwords.Passwords[service] = password
	dataToEncrypt, _ := json.Marshal(passwords)
	key, _ := deriveKey([]byte(masterPassword), salt)
	encrypted, _ := encrypt(dataToEncrypt, key)

	if err := save(encrypted, salt); err != nil {
		fmt.Println("Error saving password store:", err)
	} else {
		fmt.Println("Password added successfully.")
	}
}

func handleGet(masterPassword, service string) {
	encryptedData, salt, err := load()
	if err != nil {
		fmt.Println("Password store not found. Add a password first.")
		return
	}

	key, err := deriveKey([]byte(masterPassword), salt)
	if err != nil {
		fmt.Println("Error deriving key:", err)
		return
	}

	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		fmt.Println("Failed to decrypt password store. Incorrect master password?")
		return
	}

	var passwords PasswordStore
	json.Unmarshal(decryptedData, &passwords)

	if pass, ok := passwords.Passwords[service]; ok {
		fmt.Printf("Password for %s: %s\n", service, pass)
	} else {
		fmt.Printf("No password found for %s\n", service)
	}
}
