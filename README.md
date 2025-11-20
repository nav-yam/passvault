# 🔒 Secure Vault: Your Digital Fort

**Secure Vault** is a desktop application designed to be the safest place for your passwords. Think of it as a high-tech, digital safe box that lives on your computer. You only need to remember one key (your Master Password) to unlock access to all your other passwords for websites, apps, and services.

## 🌟 Why Use Secure Vault?

In today's digital world, using the same password everywhere is dangerous, but remembering unique passwords for every site is impossible. Secure Vault solves this by:
1.  **Remembering everything for you**: You store your complex passwords here.
2.  **Keeping them safe**: We use military-grade encryption (AES-256) to scramble your data so only you can read it.
3.  **Helping you create better passwords**: Our built-in tools generate passwords that hackers can't guess.

## 💎 Key Features Explained

### 🛡️ The Vault (Your Secure Container)
This is the heart of the application. It's an encrypted database where your information lives. Just like a physical bank vault, it requires a specific key to open.

### 🔑 Master Password (The Only Key)
This is the **one** password you need to remember. It unlocks your Vault.
*   **Important**: We do **not** store this password. If you lose it, we cannot recover your data. This ensures that even if our servers were compromised, your data would remain safe because only *you* have the key.

### 🎲 Password Generator (The Randomizer)
Humans are bad at creating random passwords (we use birthdays, pet names, etc.). Our Generator creates long, chaotic strings of characters (like `Kj#9$mP2!v`) that are mathematically nearly impossible to guess.

### 📊 Strength Meter (The Judge)
Whenever you type a password, our Strength Meter analyzes it in real-time. It checks for common patterns, length, and complexity, giving you a color-coded score (Red = Weak, Green = Strong).

### ⏱️ Auto-Lock (The Guard)
If you walk away from your computer or minimize the app, Secure Vault automatically locks itself after 5 minutes. This prevents prying eyes from seeing your data if you forget to close the app.

### 📋 Clipboard Wiper (The Cleaner)
When you copy a password to paste it into a website, it stays in your computer's "clipboard" memory. Secure Vault automatically wipes this memory after 60 seconds so you don't accidentally paste your password into a chat window or email later.

### 🎨 Premium Themes (The Look)
Security doesn't have to be boring. Customize your experience with beautiful themes, including a "Premium" gradient mode, "Dark" mode for low light, and calming "Forest" or "Cyan" themes.

## 🚀 How to Install

### For Windows Users
1.  Download the application installer.
2.  Run the installer (`.exe` file).
3.  Follow the on-screen prompts.
4.  Launch **Secure Vault** from your desktop or start menu.

### For Developers (Building from Source)
1.  Ensure you have **Node.js** installed.
2.  Clone this repository.
3.  Run `npm install` in both `client` and `server` folders.
4.  Start the app with `npm start`.

## 🔒 Technical Security Details (For the Tech-Savvy)
*   **Encryption**: AES-256-GCM (The standard used by governments and banks).
*   **Key Derivation**: Argon2id (Resistant to brute-force attacks by powerful computers).
*   **Zero-Knowledge**: The server never sees your Master Password or unencrypted data.
*   **Local Storage**: Your encrypted vault is stored locally on your device for maximum control.

---
*Secure Vault is an open-source project dedicated to making digital security accessible to everyone.*
