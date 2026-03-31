import streamlit as st

st.set_page_config(page_title="Password Tool", page_icon="🔐", layout="centered")

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
        # TODO: implement generate_password() in generator.py
        password = "PLACEHOLDER — implement generate_password()"
        st.code(password)
        st.info("Entropy: — bits (implement calculate_entropy())")

# ── Tab 2: Hash Password ──────────────────────────────────────────────────────
with tab2:
    st.header("Hash Password")
    st.write("Enter a password to hash it using Argon2.")

    password_input = st.text_input("Password", type="password", key="hash_input")
    algorithm = st.radio("Algorithm", ["Argon2", "SHA-256"], horizontal=True)

    if st.button("Hash Password", key="hash"):
        if password_input:
            # TODO: implement hash_password() in hasher.py
            st.code("PLACEHOLDER — implement hash_password()")
        else:
            st.warning("Please enter a password.")

# ── Tab 3: Verify Password ────────────────────────────────────────────────────
with tab3:
    st.header("Verify Password")
    st.write("Check if a password matches a stored hash.")

    verify_password = st.text_input("Password", type="password", key="verify_pass")
    verify_hash = st.text_area("Hash", key="verify_hash", height=100)

    if st.button("Verify", key="verify"):
        if verify_password and verify_hash:
            # TODO: implement verify_password() in hasher.py
            st.info("PLACEHOLDER — implement verify_password()")
        else:
            st.warning("Please fill in both fields.")