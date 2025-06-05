# Go CLI Password Safe

## Description

A simple and secure command-line password manager built using Go. The application enables users to securely store and retrieve passwords for different services, all encrypted with a master password.

### Security Disclaimer

This is an educational project demonstrating Go programming concepts, including CLI design and cryptography. Note: It has not undergone professional security audits. Please use it at your own risk and avoid storing critical passwords.

## Features

- Secure Storage: Passwords are encrypted in a local file (passwords.safe).
- Strong Encryption: Utilizes AES-256-GCM for authenticated encryption.
- Robust Key Derivation: Employs scrypt for deriving the encryption key from the master password, enhancing resistance against brute-force attacks.
- Simple CLI Interface: Conveniently manage passwords through the terminal.
- Secure Terminal Input: Hides the master password input from the screen.
- List Services: View all saved services without exposing passwords.

## Prerequisites

To build and run the application, you need:

- Go version 1.21 or newer

## Installation & Setup

1. Clone the repository:
    - If using a Git repository:
      ```
      git clone https://github.com/your-username/go-password-safe.git
      cd go-password-safe
      ```
    - If local project, ensure all Go files are in one directory.

2. Install Dependencies:
    ```
    go mod tidy
    ```

3. Build the Executable:
    ```
    go build
    ```
    This will create an executable file named `go-password-safe` (or `go-password-safe.exe` on Windows).

## Usage

- Master Password is implicitly set during the first password addition.

**Adding a New Password:**

```
./go-password-safe add --service <service_name> --password <password>
```

**Retrieving a Saved Password:**

```
./go-password-safe get --service <service_name>
```

**Listing All Saved Services:**

```
./go-password-safe list
```

Example Output:

```
Enter master password:
Stored services:
1. github.com
2. google.com
```

## How It Works

- Master Password: Provided for all operations, not stored.
- Salt: Unique random salt generated and stored in the `passwords.safe` file.
- Key Derivation (scrypt): Uses scrypt to create a strong encryption key.
- Encryption (AES-GCM): Encrypts service passwords using AES-256-GCM for confidentiality and authenticity.
- Storage: Salt and encrypted data stored in `passwords.safe`.

## Future Improvements

Enhancements could include:

- [x] `list` command to display saved services.
- [ ] `delete` command to remove a password entry.
- [ ] `update` command to change an existing password.
- [ ] `generate` command for creating strong, random passwords.
- [ ] Copy password to clipboard functionality.
