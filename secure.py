# develop a Streamlit based secure data storage and retrieval system
import streamlit as st
# Removed unused import hashlib
import json
import os
import time
from cryptography.fernet import Fernet  # Ensure the cryptography package is installed
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac  # Removed unused sha256

# Constants
DATA_FILE = 'secure_data.json'
SALT = b'secret_salt'  
LOCKOUT_DURATION = 60  # seconds

# Initialize session state
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None

if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0

if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# Load and save data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Password hashing and key generation
def generate_key(password):
    key = pbkdf2_hmac('sha256', password.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encryption and decryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# UI and Navigation
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)  # Ensure Streamlit is installed and correctly imported

# Home
if choice == "Home":
    st.subheader("Welcome to My 🔐 Data Encryption System Using Streamlit!")
    st.markdown("""
    - Users store data with a unique passkey.
    - Users decrypt data by providing the correct passkey.
    - Multiple failed attempts result in a forced reauthorization (login page).
    - The system operates entirely in memory without external databases.
    """)

# Register
elif choice == "Register":
    st.subheader("✏️ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": ""
                }
                save_data(stored_data)
                st.success("✅ User registered successfully")
        else:
            st.error("Both fields are required.")

# Login
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username and password:
            if username in stored_data:
                hashed_password = stored_data[username]["password"]
                if hash_password(password) == hashed_password:
                    st.session_state.authenticated_user = username
                    st.session_state.login_attempts = 0
                    st.success("✅ Login successful!")
                else:
                    st.session_state.login_attempts += 1
                    remaining_attempts = 3 - st.session_state.login_attempts
                    st.error(f"❌ Invalid password. Attempts left: {remaining_attempts}")
            else:
                st.error("❌ Username not found.")

        if st.session_state.login_attempts >= 3:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.error("❌ Too many attempts. Please wait 60 seconds.")
            st.stop()

# Store Data
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first")
    else:
        st.subheader("🔒 Encrypted Store Data")
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Enter passkey", type="password")

        if st.button("Store Data"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"] = encrypted_data
                save_data(stored_data)
                st.success("✅ Data stored successfully!")
            else:
                st.error("Both fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first")
    else:
        st.subheader("🔑 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", "")

        if not user_data:
            st.info("No data found for this user.")
        else:
            st.write("🔒 Encrypted Data:")
            st.code(user_data, language="python")

            encrypted_input = st.text_area("Enter encrypted data to decrypt", value=user_data)
            passkey = st.text_input("Enter passkey", type="password")

            if st.button("Decrypt Data"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("✅ Decrypted Data:")
                    st.code(result, language="python")
                else:
                    st.error("❌ Invalid passkey or data.")
