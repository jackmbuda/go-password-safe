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
	// Command-line flag sets
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	addService := addCmd.String("service", "", "The service to add a password for.")
	addPassword := addCmd.String("password", "", "The password for the service. If omitted, you will be prompted.")

	getCmd := flag.NewFlagSet("get", flag.ExitOnError)
	getService := getCmd.String("service", "", "The service to get the password for.")

	// Define a new FlagSet for the list command
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: A subcommand ('add', 'get', or 'list') is required.")
		printUsage()
		os.Exit(1)
	}

	// Prompt for master password (required for all commands)
	fmt.Print("Enter master password: ")
	masterPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading master password:", err)
		os.Exit(1)
	}
	fmt.Println() // Add a newline after the hidden password input
	masterPassword := string(masterPasswordBytes)

	// Route to the correct subcommand handler
	switch os.Args[1] {
	case "add":
		addCmd.Parse(os.Args[2:])
		if *addService == "" {
			fmt.Fprintln(os.Stderr, "Error: --service flag is required for the 'add' command.")
			addCmd.PrintDefaults()
			os.Exit(1)
		}

		// If password flag is empty, prompt for it securely
		var actualPassword string
		if *addPassword == "" {
			fmt.Print("Enter password for service '" + *addService + "': ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error reading service password:", err)
				os.Exit(1)
			}
			fmt.Println()
			actualPassword = string(passwordBytes)
		} else {
			actualPassword = *addPassword
		}

		handleAdd(masterPassword, *addService, actualPassword)

	case "get":
		getCmd.Parse(os.Args[2:])
		if *getService == "" {
			fmt.Fprintln(os.Stderr, "Error: --service flag is required for the 'get' command.")
			getCmd.PrintDefaults()
			os.Exit(1)
		}
		handleGet(masterPassword, *getService)

	case "list":
		// New case for the list command
		listCmd.Parse(os.Args[2:])
		handleList(masterPassword)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown subcommand '%s'\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// printUsage prints the main usage information for the tool.
func printUsage() {
	fmt.Println("\nUsage:")
	fmt.Println("  go-password-safe <command> [arguments]")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  add    Add a new password to the safe")
	fmt.Println("  get    Get a password from the safe")
	fmt.Println("  list   List all services in the safe")
}

func handleAdd(masterPassword, service, password string) {
	var passwords PasswordStore
	var salt []byte

	encryptedData, loadedSalt, err := load()
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, this is the first time setup
			fmt.Println("Initializing new password store...")
			passwords.Passwords = make(map[string]string)
			salt, err = newSalt()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error creating new salt:", err)
				return
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error loading password store:", err)
			return
		}
	} else {
		// File exists, decrypt and load
		salt = loadedSalt
		key, err := deriveKey([]byte(masterPassword), salt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error deriving key:", err)
			return
		}
		decryptedData, err := decrypt(encryptedData, key)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to decrypt password store. Incorrect master password?")
			return
		}
		if err := json.Unmarshal(decryptedData, &passwords); err != nil {
			fmt.Fprintln(os.Stderr, "Error unmarshalling password store:", err)
			return
		}
		if passwords.Passwords == nil { // Ensure map is initialized if store was empty but valid
			passwords.Passwords = make(map[string]string)
		}
	}

	// Add or update the password
	passwords.Passwords[service] = password
	dataToEncrypt, err := json.Marshal(passwords)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error marshalling passwords:", err)
		return
	}

	// Re-derive key for encryption
	key, err := deriveKey([]byte(masterPassword), salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error deriving key for saving:", err)
		return
	}

	encrypted, err := encrypt(dataToEncrypt, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error encrypting password data:", err)
		return
	}

	if err := save(encrypted, salt); err != nil {
		fmt.Fprintln(os.Stderr, "Error saving password store:", err)
	} else {
		fmt.Println("Password added/updated successfully for service:", service)
	}
}

func handleGet(masterPassword, service string) {
	encryptedData, salt, err := load()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Password store not found. Add a password first using the 'add' command.")
		} else {
			fmt.Fprintln(os.Stderr, "Error loading password store:", err)
		}
		return
	}

	key, err := deriveKey([]byte(masterPassword), salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error deriving key:", err)
		return
	}

	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to decrypt password store. Incorrect master password?")
		return
	}

	var passwords PasswordStore
	if err := json.Unmarshal(decryptedData, &passwords); err != nil {
		fmt.Fprintln(os.Stderr, "Error unmarshalling password store:", err)
		return
	}

	if pass, ok := passwords.Passwords[service]; ok {
		fmt.Printf("Password for %s: %s\n", service, pass)
	} else {
		fmt.Printf("No password found for service: %s\n", service)
	}
}

// New handler function for the 'list' command
func handleList(masterPassword string) {
	encryptedData, salt, err := load()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Password store not found or is empty. Add a password first.")
		} else {
			fmt.Fprintln(os.Stderr, "Error loading password store:", err)
		}
		return
	}

	key, err := deriveKey([]byte(masterPassword), salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error deriving key:", err)
		return
	}

	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to decrypt password store. Incorrect master password?")
		return
	}

	var passwords PasswordStore
	if err := json.Unmarshal(decryptedData, &passwords); err != nil {
		fmt.Fprintln(os.Stderr, "Error unmarshalling password store:", err)
		return
	}

	if len(passwords.Passwords) == 0 {
		fmt.Println("No services found in the password store.")
		return
	}

	fmt.Println("Stored services:")
	i := 1
	for serviceName := range passwords.Passwords {
		fmt.Printf("%d. %s\n", i, serviceName)
		i++
	}
}
