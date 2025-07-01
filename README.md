# 🔐 Crypt_Guard

![Banner](https://via.placeholder.com/800x200.png?text=Crypt_Guard+Banner)  
*Placeholder for banner image: 52406b37-ef5a-4037-8fdb-5ba04ed47077.png*

> Developed by **Y. Janboubi** | Version: `1.0`

## 📖 Overview

**Crypt_Guard** is a robust, cryptographic utility designed for encrypting binary files. It employs a hybrid encryption chain combining **XOR**, **RC4**, and **AES** algorithms to ensure secure data protection. Additionally, it features a **brute-force decryption module** to evaluate cryptographic resilience and support reverse-engineering scenarios.

---

## ✨ Key Features

- 🔒 **Hybrid Encryption Chain**: Seamlessly integrates XOR, RC4, and AES for layered security.
- 🔍 **Brute-Force Decryption**: Supports dictionary-based and brute-force key recovery for testing and analysis.
- 🛡️ **Security Testing**: Tailored for penetration testers, Red teaming, and security researchers.
- 📦 **Portable Design**: Lightweight, standalone executable for easy deployment.

---

## 🔑 Supported Encryption Algorithms

**Crypt_Guard** supports the following cryptographic algorithms:

- **XOR**: A lightweight, bitwise operation for basic obfuscation.
- **RC4**: A stream cipher known for its speed and use in legacy protocols.
- **AES**: Advanced Encryption Standard, a secure block cipher for protecting sensitive data.
---

## 🚀 Usage

**Crypt_Guard** is a command-line tool designed for ease of use. Specify the encryption algorithm and target binary file to perform encryption or analysis.

### 🛠️ Command Syntax

```bash
Crypt_Guard.exe <encryption_type> <input_file>
```

- `<encryption_type>`: `xor`, `rc4`, or `aes`
- `<input_file>`: Path to the binary file (e.g., `data.bin`)

### 📋 Example Commands

- **Encrypt a file using XOR:**
```bash
Crypt_Guard.exe xor data.bin
```

- **Encrypt a file using RC4:**
```bash
Crypt_Guard.exe rc4 data.bin
```

- **Encrypt a file using AES:**
```bash
Crypt_Guard.exe aes data.bin
```
---

## 🛠️ Installation

### 📋 Prerequisites

To build **Crypt_Guard** from source, ensure the following dependencies are installed:

- **c/C++ Compiler**: GCC, Clang, or equivalent
- **Build Tools**: Make or CMake (depending on the build system)
- **Git**: For cloning the repository

### 🧩 Building from Source

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Crypt_Guard.git
   ```

2. **Navigate to the Project Directory**:
   ```bash
   cd Crypt_Guard
   ```

3. **Build the Project**:
 - **Using Make**:
   ```bash
   make
   ```
 - **Using CMake**:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

### 📦 Pre-Compiled Binaries

Pre-compiled binaries for Windows are available in the [Releases](https://github.com/YOUR_USERNAME/Crypt_Guard/releases) section of the repository. Download the Windows binary and follow the provided instructions for usage.

---

## 📝 Notes

- Ensure you havefacial hair have the necessary permissions to read and write the target binary files.
- For detailed configuration options, refer to the [project documentation](https://github.com/YOUR_USERNAME/Crypt_Guard/wiki).

---

## 📬 Contact

For questions, bug reports, or contributions, please visit the [GitHub repository](https://github.com/YOUR_USERNAME/Crypt_Guard) or contact the developer at [your.email@example.com].

---

*Developed with security in mind by Y. Janboubi.*  
*Last Updated: July 2025*

