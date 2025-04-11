import streamlit as st
from cryptography.fernet import Fernet

# Title
st.title("🔐 Secure data Encryption System")
st.write("Encrypt and Decrypt your messages safely using Fernet (AES 128 CBC)")

# Generate or use existing key
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

fernet = Fernet(st.session_state.fernet_key)

# Option selection
option = st.radio("Select Action", ["Encrypt Text", "Decrypt Text"])

# Text input
text_input = st.text_area("Enter your text here")

# Button and Result
if option == "Encrypt Text":
    if st.button("🔒 Encrypt"):
        if text_input:
            encrypted = fernet.encrypt(text_input.encode())
            st.success("Encrypted Text:")
            st.code(encrypted.decode(), language='text')
        else:
            st.warning("Please enter some text.")
elif option == "Decrypt Text":
    if st.button("🔓 Decrypt"):
        if text_input:
            try:
                decrypted = fernet.decrypt(text_input.encode())
                st.success("Decrypted Text:")
                st.code(decrypted.decode(), language='text')
            except Exception as e:
                st.error("❌ Decryption failed. Invalid input or wrong key.")
        else:
            st.warning("Please enter the encrypted text.")

# Show Key
with st.expander("📌 Show Secret Key (for advanced use)"):
    st.code(st.session_state.fernet_key.decode(), language='text')
