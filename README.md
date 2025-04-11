# 🔐 Streamlit Secure Data Encryption App

This is a **Streamlit-based encryption and decryption system** that uses **Fernet (symmetric encryption)** and **SHA-256 hashing** to securely store and retrieve sensitive data.

---

## 🚀 Features

- 🔒 Encrypt and securely store any text data  
- 🔑 Protect data with a user-defined passkey  
- 🧠 Passkeys are hashed using SHA-256 for added security  
- ❌ Three incorrect passkey attempts will lock access and redirect to the login page  
- 🧪 Simple login system for admin reset (default password: `admin123`)  
- 🖥️ Clean and intuitive Streamlit interface  

---

## 🛠️ Technologies Used

- [Streamlit](https://streamlit.io/)
- [Cryptography (Fernet)](https://cryptography.io/en/latest/)
- [Hashlib (SHA-256)](https://docs.python.org/3/library/hashlib.html)

---

## 💻 Installation & Running

### ✅ Prerequisites

Make sure you have Python 3.7+ installed.

Install required libraries:

```bash
pip install streamlit cryptography
