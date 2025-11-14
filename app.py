import streamlit as st
from rsa_extended import (
    generate_keys,
    save_keys_json,
    load_keys_json,
    encrypt_text,
    decrypt_text_b64,
)

st.set_page_config(page_title="RSA Demo", layout="centered")

st.title("RSA Cryptosystem Demo Using the Extended Euclidean Algorithm")

# -------------------------
# Sidebar: Key Management
# -------------------------
st.sidebar.header("Key management")
bits = st.sidebar.select_slider(
    "Key size (bits)", options=[1024, 1536, 2048], value=2048
)
e = st.sidebar.number_input("Public exponent e", value=65537, step=2)

# Generate keys and save to keys.json
if st.sidebar.button("Generate keys"):
    try:
        pub, priv = generate_keys(bits=bits, e=e)
        path = save_keys_json(pub, priv, path="keys.json")
        st.sidebar.success(f"Saved keys to {path}")
        st.session_state["pub"] = pub
        st.session_state["priv"] = priv
    except Exception as ex:
        st.sidebar.error(str(ex))

st.sidebar.markdown("---")

# Load existing keys.json
if st.sidebar.button("Load keys.json"):
    try:
        pub, priv = load_keys_json("keys.json")
        st.session_state["pub"] = pub
        st.session_state["priv"] = priv
        st.sidebar.success("Loaded keys.json")
    except Exception as ex:
        st.sidebar.error(str(ex))

# -------------------------
# Public Key Display
# -------------------------
st.header("Public key")
if "pub" in st.session_state:
    e_val, n_val = st.session_state["pub"]
    st.code(f"e = {e_val}\nn = {n_val}")
else:
    st.write("Generate or load keys.json to proceed.")

# -------------------------
# Encrypt Section
# -------------------------
st.header("Encrypt")
message = st.text_area(
    "Plaintext", value="hello master project (demo)", height=80
)

if st.button("Encrypt (using loaded keys)"):
    if "pub" not in st.session_state:
        st.error("No public key loaded. Generate or load keys.json.")
    else:
        try:
            ct = encrypt_text(message, st.session_state["pub"])
            st.success("Ciphertext (base64):")
            st.code(ct)
            st.session_state["last_cipher"] = ct
        except Exception as ex:
            st.error(str(ex))

# -------------------------
# Decrypt Section
# -------------------------
st.header("Decrypt")

use_last = st.checkbox("Use last generated ciphertext")
cipher_input = st.text_input(
    "Ciphertext (base64)",
    value=(st.session_state.get("last_cipher", "") if use_last else ""),
)

if st.button("Decrypt"):
    if "priv" not in st.session_state:
        st.error("No private key loaded. Generate or load keys.json.")
    else:
        try:
            pt = decrypt_text_b64(cipher_input, st.session_state["priv"])
            st.success("Decrypted plaintext:")
            st.write(pt)
        except Exception as ex:
            st.error(str(ex))
