# 🔐 Secure Client-Side Password Vault

A robust and secure browser-based password manager designed with a **zero-trust** approach, storing all encrypted password data **locally** on the user's device using **IndexedDB**. This project emphasizes strong **client-side encryption** and minimal server interaction for maximum user control and privacy.

---

## 🧠 About the Project

This project implements a **client-side password vault**, allowing users to manage credentials without relying on cloud storage. All encryption/decryption happens **locally in the browser**.

A lightweight **Node.js server** is used only to serve static files, significantly reducing the attack surface found in traditional web apps.

> The system adheres strictly to **zero-trust principles**, ensuring no sensitive data is transmitted or stored unencrypted on any server.

---

## 🚀 Features

- **Master Password Authentication**  
  Secure vault access using a master password — never stored.

- **Secure Client-Side Encryption**  
  All entries (URL, username, password, notes) are encrypted using AES-256-GCM directly in the browser.

- **Local Storage with IndexedDB**  
  Vault data is stored locally and never leaves the user’s device.

- **CRUD Functionality**  
  Add, edit, delete, and view password entries.

- **Password Generator**  
  Strong, customizable password generation with a strength indicator.

- **Clipboard Copying**  
  One-click copy with automatic clipboard clearing after a short delay.

- **Vault Export & Import**  
  Export encrypted vault to JSON for backup and re-import using the master password.

- **Change Master Password**  
  Re-encrypt the vault with a new password securely.

- **Auto-Lock**  
  Automatically locks the vault after inactivity.

- **Responsive UI**  
  Clean, modern interface built with **Tailwind CSS**.

---

## 🔒 Security Highlights

- **Zero-Trust Data Handling**  
  Data never leaves the browser unencrypted.

- **Strong Key Derivation (PBKDF2)**  
  - PBKDF2 with SHA-256 and 100,000 iterations  
  - Unique salt per vault  
  - Master password never stored

- **AES-256-GCM Encryption**  
  - Authenticated encryption for confidentiality and integrity  
  - Unique IVs per operation

- **Inherent Server-Side Protection**  
  Server-side vulnerabilities like SQL injection, CSRF, SSRF, etc., are irrelevant due to client-side design.

- **Clickjacking Mitigation**  
  Use of `helmet.js` for setting HTTP security headers like `X-Frame-Options`.

- **Client-Side XSS Awareness**  
  Careful DOM handling and input sanitization reduce risk of XSS.

---

## 🧰 Technologies Used

### Frontend

- **HTML5** – Structure
- **Tailwind CSS** – Utility-first styling
- **JavaScript (ES6+)** – Logic for encryption, storage, UI
- **Web Crypto API** – PBKDF2, AES-GCM
- **IndexedDB API** – Local encrypted storage

### Backend (Static File Server)

- **Node.js**
- **Express.js**
- **Helmet.js**

---

## 🛠️ Getting Started

### ✅ Prerequisites

- [Node.js (LTS)](https://nodejs.org/)
- npm (comes with Node.js)

### 📦 Installation

```bash
git clone https://github.com/manojbn08/Secure-Vault.git
cd Secure-Vault
npm install
## ▶️ Running the Application

```bash
npm start
Visit: [http://localhost:3000](http://localhost:3000)

---

## 💡 Usage Guide

**First Visit:**  
Set a new master password.

**Returning Users:**  
Enter your master password to unlock the vault.

---

## ⚠️ Important Notes

**Browser-Specific Data:**  
IndexedDB is specific to each browser and domain. Switching browsers or clearing site data resets the vault unless you've exported it.

**Master Password:**  
Your vault's security depends entirely on your master password. Choose something **strong and unique**, and **do not forget it** — it **cannot** be recovered.

---

Made with ❤️ to keep your credentials safe.
