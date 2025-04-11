import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a Fernet key (this should be static in real apps)
if "fernet_key" not in st.session_state:
    st.session_state["fernet_key"] = Fernet.generate_key()

cipher = Fernet(st.session_state["fernet_key"])

# In-memory storage
if "stored_data" not in st.session_state:
    st.session_state["stored_data"] = {}

# Track failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

# Simple session login flag
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False


# Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(enc_text):
    return cipher.decrypt(enc_text.encode()).decode()


# Streamlit UI
st.set_page_config(page_title="Secure Encryption", page_icon="🔒")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📂 Navigation", menu)


# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data
elif choice == "Store Data":
    st.subheader("📝 Store Data Securely")

    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("🔒 Encrypt & Save"):
        if user_data and passkey:
            enc_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)

            st.session_state["stored_data"][enc_text] = {"encrypted_text": enc_text, "passkey": hashed_pass}

            st.success("✅ Data encrypted and stored successfully!")
            st.code(enc_text, language="text")
        else:
            st.warning("⚠️ Please fill in both fields.")

# Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")

    if st.session_state["failed_attempts"] >= 3 and not st.session_state["logged_in"]:
        st.warning("❌ Too many failed attempts! Please login.")
        st.switch_page("Login")

    enc_input = st.text_area("Enter encrypted data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("🔍 Decrypt"):
        if enc_input and passkey:
            hashed_input = hash_passkey(passkey)

            data = st.session_state["stored_data"].get(enc_input)

            if data and data["passkey"] == hashed_input:
                result = decrypt_data(enc_input)
                st.success("✅ Decryption successful!")
                st.code(result, language="text")
                st.session_state["failed_attempts"] = 0  # reset
            else:
                st.session_state["failed_attempts"] += 1
                attempts_left = 3 - st.session_state["failed_attempts"]
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                if st.session_state["failed_attempts"] >= 3:
                    st.warning("🔒 Redirecting to login page...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please enter all fields.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Login Page")

    login_input = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_input == "admin123":
            st.success("✅ Login successful!")
            st.session_state["failed_attempts"] = 0
            st.session_state["logged_in"] = True
            st.experimental_rerun()
        else:
            st.error("❌ Wrong master password!")
