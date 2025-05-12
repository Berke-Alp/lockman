# LockMan

LockMan is a command-line file encryption and decryption tool built with Rust. It provides a simple, secure, and efficient way to lock (encrypt) and unlock (decrypt) files using AES-256-GCM encryption.

You can also find LockMan on [crates.io](https://crates.io/crates/lockman).

---

## Features
- **AES-Based Encryption**: Uses AES-256-GCM encryption for high security and performance.
- **Password-Based Key Derivation**: Employs PBKDF2 (HMAC-SHA256) to securely derive encryption keys from user-provided passwords.
- **Mandatory File Metadata**: Ensures proper decryption with securely encoded metadata, like block size, salt, and encryption iterations.
- **Interactive CLI**: Includes intuitive commands for both locking and unlocking files, with user prompts for overwriting files or cleanup.
- **Cross-Platform Compatibility**: Works seamlessly on Linux, macOS, and Windows.

---

## Installation

### Prerequisites
To build LockMan from source, ensure you have:
- **Rust** (the latest stable version recommended) installed. You can install Rust from [rust-lang.org](https://www.rust-lang.org/).
- Alternatively, you can install it directly from [crates.io](https://crates.io/crates/lockman) with `cargo`:
  ```bash
  cargo install lockman
  ```

### Build Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/Berke-Alp/lockman.git
   cd lockman
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. The compiled binary will be available at `./target/release/lockman`.

4. (Optional) Install globally:
   ```bash
   cargo install --path .
   ```

   This makes the `lockman` command globally available in your system.

---

## Important Note on Versioning

LockMan is currently in its early development phase (version `0.x.x`). This means the following:

1. **Non-Stable Structures**: The byte structure of files and the definition of enums may change at any time during development. This can result in incompatibilities between versions.
2. **Not Suitable for Real-World Use**: LockMan's current state is not intended for real-world applications or personal usage. Use it for testing and development purposes only.
3. **Backwards Compatibility in the Future**: Starting with version `1.0.0`, all file structures and related dependencies will be stabilized, and backwards compatibility will be guaranteed moving forward.

We recommend waiting for the `1.0.0` release if you require a stable and reliable solution. Stay tuned for updates!

---

## Usage

LockMan provides an easy-to-use CLI for securely locking and unlocking files.

### Commands

#### Lock a file
Encrypt a file with a password:
```bash
lockman lock <FILE> <PASSWORD>
```

- **`<FILE>`**: Path to the file to lock.
- **`<PASSWORD>`**: Password used to encrypt the file.

Example:
```bash
lockman lock example.txt secret123
```

Options:
- **Interactive Prompts**: If a locked file already exists, LockMan will prompt you to confirm overwriting it. You can also choose to delete the original file after encryption.

#### Unlock a file
Decrypt a file with a password:
```bash
lockman unlock <FILE> <PASSWORD>
```

- **`<FILE>`**: Path to the encrypted file (must end in `.lockman`).
- **`<PASSWORD>`**: Password used during encryption.

Example:
```bash
lockman unlock example.txt.lockman secret123
```

Options:
- **Interactive Prompts**: If the decrypted file already exists, LockMan will prompt you to confirm overwriting it. You can also choose to delete the locked file after decryption.

---

## How It Works

1. **Password-Based Key Derivation**:
   - LockMan uses PBKDF2 with HMAC-SHA256 to derive a secure 256-bit key from the password and a randomly generated salt.
   - Salts ensure that the same password generates unique encryption keys for different files.

2. **File Metadata**:
   - Encrypted files include a file header that stores critical metadata such as:
      - Block size and count.
      - Key derivation iterations (default: 310,000).
      - Salt size and content for key reproducibility.

3. **AES-GCM Encryption**:
   - Files are encrypted in blocks (default: 16 KB per block) for efficient processing.
   - Each block uses a unique, randomly generated 96-bit nonce to ensure security.
   - An AES-GCM authentication tag (16 bytes) is appended to each encrypted block for integrity verification during decryption.

---

## Example Workflow

1. Start with a text file `example.txt`:
   ```bash
   echo "This is a secret file." > example.txt
   ```

2. Lock the file with a password:
   ```bash
   lockman lock example.txt mysecurepassword
   ```
   The tool outputs a new file `example.txt.lockman`.

3. Unlock the file to retrieve its original contents:
   ```bash
   lockman unlock example.txt.lockman mysecurepassword
   ```
   This restores the original `example.txt`.

4. (Optional) Clean up:
   - LockMan provides prompts to delete the original or locked files for convenience during encryption or decryption.

---

## To-Do List

Planned improvements to LockMan:
- [ ] Save the original file extension in the header to make restoration seamless.
- [ ] Add RSA encryption support for scenarios requiring public-private key pairs.
- [ ] Enable piping data from `stdin` and outputting to `stdout` for advanced workflows (e.g., integrating with shell scripts).
- [ ] Improve logging and verbosity levels to provide more detailed and user-friendly output.
- [ ] Support configurable block sizes for optimized performance in various scenarios.

---

## Limitations

- LockMan cannot encrypt directories (only single files are supported).
- Password security is vital — poorly chosen passwords can compromise the encryption's effectiveness.
- Encrypted files depend on metadata stored in the file. Any corruption can prevent successful decryption.

---

## License

This project is licensed under the **MIT** license. See the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Here's how you can help:
1. Open a [GitHub Issue](https://github.com/Berke-Alp/lockman/issues) if you encounter a bug or have a feature request.
2. Fork the repository, make your changes, and submit a pull request.

Before submitting, ensure:
- Your changes include relevant tests to ensure functionality.
- Your code follows idiomatic Rust practices.

---

## Acknowledgments

This project uses the following crates to deliver its functionality:
- [AES-GCM](https://crates.io/crates/aes-gcm): High-performance authenticated encryption.
- [Clap](https://crates.io/crates/clap): Argument parsing for the CLI.
- [PBKDF2](https://crates.io/crates/pbkdf2): Password-based key derivation.
- [SHA2](https://crates.io/crates/sha2): Cryptographic hashing for HMAC and PBKDF2.
- [Bincode](https://crates.io/crates/bincode): Binary encoding for efficient header serialization.

---

## Support

If you find LockMan useful, feel free to star the repository or share it with others who need file encryption solutions! Your support means the world. 😊
