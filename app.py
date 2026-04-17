import streamlit as st
from generator import generate_password, calculate_entropy
from hasher import hash_password, verify_password

st.set_page_config(page_title="Password Tool", page_icon="🔐", layout="centered")

st.markdown("""
    <style>
    .stAlert p {
        color: white !important;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Password Security Tool")
st.caption("Group K Project")

tab1, tab2, tab3 = st.tabs(["Generate Password", "Hash Password", "Verify Password"])

# ── Tab 1: Password Generator ─────────────────────────────────────────────────
with tab1:
    st.header("Password Generator")
    st.write("Configure options and generate a secure password.")

    length = st.slider("Password length", min_value=8, max_value=64, value=16)
    use_digits = st.checkbox("Include digits", value=True)
    use_symbols = st.checkbox("Include symbols", value=True)
    use_uppercase = st.checkbox("Include uppercase letters", value=True)

    if st.button("Generate Password", key="gen"):
        password = generate_password(length, use_digits, use_symbols, use_uppercase)
        st.code(password)
        entropy = calculate_entropy(password)
        
        if entropy < 40:
            st.error(f"🔴 Entropy: {entropy:.2f} bits — Weak")
        elif entropy < 60:
            st.warning(f"🟡 Entropy: {entropy:.2f} bits — Fair")
        elif entropy < 80:
            st.success(f"🟢 Entropy: {entropy:.2f} bits — Strong")
        else:
            st.success(f"💪 Entropy: {entropy:.2f} bits — Very Strong")

# ── Tab 2: Hash Password ──────────────────────────────────────────────────────
with tab2:
    st.header("Hash Password")
    st.write("Enter a password to hash it using Argon2.")

    password_input = st.text_input("Password", type="password", key="hash_input")
    algorithm = st.radio("Algorithm", ["Argon2", "SHA-256"], horizontal=True)

    if st.button("Hash Password", key="hash"):
        if password_input:
            hashed = hash_password(password_input, algorithm)
            st.code(hashed)
            st.success("✅ Password hashed successfully!")
        else:
            st.warning("Please enter a password.")

# ── Tab 3: Verify Password ────────────────────────────────────────────────────
with tab3:
    st.header("Verify Password")
    st.write("Check if a password matches a stored hash.")

    verify_pass_input = st.text_input("Password", type="password", key="verify_pass")
    verify_hash = st.text_area("Hash", key="verify_hash", height=100)

    if st.button("Verify", key="verify"):
        if verify_pass_input and verify_hash:
            # Extract algorithm from hash format (Argon2 hashes start with $argon2)
            algo = "Argon2" if verify_hash.startswith("$argon2") else "SHA-256"
            is_valid = verify_password(verify_pass_input, verify_hash, algo)
            if is_valid:
                st.success("✅ Password matches the hash!")
            else:
                st.error("❌ Password does not match the hash.")
        else:
            st.warning("Please fill in both fields.")