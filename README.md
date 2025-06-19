Secure Client-Side Password Vault
A robust and secure browser-based password manager designed with a zero-trust approach, storing all encrypted password data locally on the user's device using IndexedDB. This project emphasizes strong client-side encryption and minimal server interaction for maximum user control and privacy.

About The Project
This project implements a client-side password vault, providing users with a secure way to manage their credentials without relying on cloud synchronization for sensitive data. It operates entirely within the user's browser, encrypting and decrypting data locally. The accompanying Node.js server is minimal, serving only static files, thus greatly reducing the attack surface commonly associated with traditional web applications.

The design philosophy adheres strictly to "zero-trust" principles, ensuring that sensitive information is never transmitted or stored unencrypted on any server.

Features
Master Password Authentication: Secure access to the vault using a single master password. The master password itself is never stored.

Secure Client-Side Encryption: All vault entries (website URL, username, password, notes) are encrypted using strong cryptographic algorithms directly in the browser before being stored.

Local Data Storage (IndexedDB): Encrypted vault data persists locally in the user's browser, ensuring data remains on their device.

Add/Edit/Delete Entries: Full CRUD (Create, Read, Update, Delete) functionality for managing password entries.

Password Generator: Generate strong, random passwords with customizable length and character sets (uppercase, lowercase, numbers, symbols). Includes a basic password strength indicator.

Copy to Clipboard: Convenient one-click copying of usernames and passwords. Sensitive data is automatically overwritten in the clipboard after a short delay for enhanced security.

Vault Export & Import: Users can export their entire encrypted vault as a JSON file for backup and re-import it, requiring their master password for re-encryption and access.

Change Master Password: Allows users to securely update their master password, re-encrypting the vault's key with the new password.

Automatic Autolock: The vault automatically locks after a period of inactivity, clearing sensitive data from memory to protect against unauthorized access when a device is left unattended.

Responsive Design: A clean and modern user interface built with Tailwind CSS, ensuring usability across various device sizes.

Security Highlights
This project's security model is built upon robust client-side implementations, inherently mitigating many common web vulnerabilities:

Zero-Trust Data Handling: No sensitive data ever leaves the client's browser unencrypted. The server acts purely as a static file server.

Strong Key Derivation (PBKDF2):

Uses PBKDF2 with SHA-256 and 100,000 iterations to derive cryptographic keys from the master password.

Incorporates a unique, randomly generated salt for each vault to prevent rainbow table attacks.

The master password is never stored.

Authenticated Encryption (AES-256-GCM):

Vault entries are encrypted using AES-256 in Galois/Counter Mode, providing both confidentiality (encryption) and integrity/authenticity (tamper detection).

Uses unique Initialization Vectors (IVs) for each encryption operation to ensure high security.

Inherent Mitigation of Server-Side Vulnerabilities:

NoSQL/SQL Injection, CSRF, SSRF, Command Injection, XXE, HTTP Request Smuggling, Web Cache Poisoning, Insecure Deserialization: These vulnerabilities are fundamentally averted by the client-side design, as there are no corresponding server-side components to exploit.

Clickjacking: Mitigation is typically handled by server-side HTTP security headers (X-Frame-Options or Content-Security-Policy: frame-ancestors), which are expected to be configured in the server.js (e.g., via helmet middleware).

Client-Side Vulnerability Awareness: While the design reduces server-side risks, continuous attention is given to preventing client-side vulnerabilities like Cross-Site Scripting (XSS) through careful DOM manipulation and input sanitization practices.

Technologies Used
Frontend:

HTML5: Structure of the web application.

CSS3 (Tailwind CSS): For modern, responsive, and utility-first styling.

JavaScript (ES6+): Core logic for encryption, decryption, IndexedDB interaction, and UI manipulation.

Web Cryptography API: Utilized for secure cryptographic operations (PBKDF2, AES-GCM).

IndexedDB API: For persistent local storage of encrypted vault data.

Backend (Static File Server Only):

Node.js: Runtime environment.

Express.js: Minimalist web framework to serve static files.

Helmet.js: Express middleware for setting various HTTP security headers, enhancing overall application security (e.g., preventing clickjacking).

Getting Started
Follow these steps to get your Secure Password Vault up and running on your local machine.

Prerequisites
Node.js (LTS version recommended)

npm (Node Package Manager, usually comes with Node.js)

Installation
Clone the repository:

git clone https://github.com/your-username/secure-password-vault.git](https://github.com/manojbn08/Secure-Vault.git
cd secure-password-vault


Install dependencies:
This project uses express and helmet for serving files.

npm install

Running the Application
Start the Node.js server:

npm start

You should see a message in your console indicating that the server is running, usually on http://localhost:3000.

Access the application:
Open your web browser and navigate to http://localhost:3000.

First-time use: You will be prompted to set up a new master password.

Subsequent visits: You will be prompted to unlock your vault with your master password.

Important Notes for Testing:
Browser-Specific Data: Remember that IndexedDB data is stored per browser and per origin. If you switch browsers or clear your browser's site data, your vault will appear empty, and you'll need to set up a new one or import an existing encrypted backup.

Master Password: The security of your vault entirely depends on the strength and secrecy of your master password. Choose a strong, unique password and do not forget it!


