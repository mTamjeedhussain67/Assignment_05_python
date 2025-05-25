import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# --- File and Key Setup ---
KEY_FILE = "fernet.key"
DATA_FILE = "stored_data.json"

# Load or create encryption key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# Load stored data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Initialize stored data
stored_data = load_data()

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Streamlit UI ---
st.set_page_config(page_title="🔐 Secure Data App by AkazBaba", layout="centered")
st.title("🛡️ Secure Data Encryption System by AkazBaba")

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# --- Pages ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("Use this app to **securely store and retrieve sensitive data**.")

elif choice == "Store Data":
    st.subheader("📁 Store Data")
    username = st.text_input("Username:")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)

            stored_data[username] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data(stored_data)
            st.success("✅ Data encrypted and saved!")
        else:
            st.error("❗ All fields are required.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    username = st.text_input("Username:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username in stored_data:
            encrypted = stored_data[username]["encrypted_text"]
            hashed_passkey = hash_passkey(passkey)

            if stored_data[username]["passkey"] == hashed_passkey:
                decrypted = decrypt_data(encrypted)
                st.success(f"✅ Your data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Reauthorization required.")
                    st.experimental_rerun()
        else:
            st.error("❗ Username not found.")

elif choice == "Login":
    st.subheader("🔑 Login Required")
    master_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # change this in production!
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized!")
            st.experimental_rerun()
        else:
            st.error("❌ Wrong master password!")
