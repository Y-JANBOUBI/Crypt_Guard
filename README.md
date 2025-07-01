<h1 align="center">🛡️ Crypt_Guard</h1>

<p align="center">
  <img src="./52406b37-ef5a-4037-8fdb-5ba04ed47077.png" alt="Crypt_Guard Banner" width="700"/>
</p>

<p align="center"><strong>Version 1.0 | Developed by Y. JANBOUBI</strong></p>

---

## 📌 Overview

**Crypt_Guard** is an advanced binary encryption and decryption tool designed for cybersecurity professionals and reverse engineers. It encrypts and protects files using **multi-layered algorithms** including:

- 🔐 XOR
- 🔐 RC4
- 🔐 AES

It includes a **brute-force decryption engine** to test encryption resilience or recover crypted binaries, making it an ideal companion for malware analysis, red teaming, and cryptanalysis exercises.

---

## ⚙️ Features

- 🔒 **Chained Encryption** – Apply XOR, RC4, and AES layers to binary files.
- 🧠 **Brute-force Decryption Engine** – Reverse encrypted binaries using dictionary/keyspace attack logic.
- 📊 **Cross-platform Binary Ready** – Works on Windows (Executable), and portable to other OSs (source-based).
- 📁 **Minimal Footprint** – Lightweight and efficient for scripting, automation, or manual testing.
- 🧪 **Ideal for Penetration Testing** – Especially useful for CTFs, forensic investigations, and red team tooling.

---

## 🚀 Getting Started

### ✅ Prerequisites

- Windows 10+ (for `Crypt_Guard.exe`)
- For source builds:
  - C++ Compiler (G++, Clang, MSVC) or Python (if interpreted)
  - OpenSSL (for AES)
  - Optional: Python 3.x (if a Python version is available)

### 📦 Installation

```bash
# Clone the repository
git clone https://github.com/YourUsername/Crypt_Guard.git
cd Crypt_Guard

# (If using source)
make build      # Or run the source directly
