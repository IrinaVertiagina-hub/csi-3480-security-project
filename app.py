import streamlit as st
import string
from generator import generate_password, calculate_entropy
from hasher import hash_password, verify_password

st.set_page_config(page_title="Password Tool", page_icon="🔐", layout="centered")

st.markdown("""
    <style>
    .stAlert p {
        /* color: white !important; */
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

    length = st.slider("Password length:", min_value=8, max_value=64, value=16)

    advanced_mode = st.toggle("Advanced Mode", value=False, help="Toggle advanced mode to supply your own character set.")

    if not advanced_mode:
        charset = ""
        charset_size = 0
        if st.checkbox("Include lowercase letters", value=True):
            charset += string.ascii_lowercase
            charset_size += 26
        if st.checkbox("Include uppercase letters", value=True):
            charset += string.ascii_uppercase
            charset_size += 26
        if st.checkbox("Include digits", value=True):
            charset += string.digits
            charset_size += 10
        if st.checkbox("Include symbols", value=True, help="Includes the following characters:  \n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"):
            charset += string.punctuation
            charset_size += 32

        if charset == "":
            st.error("Please select at least one character option.")
            input_valid = False
        else:
            input_valid = True
    else:
        charset = st.text_input("Possible characters:", help="Each character included is randomly selected from when generating the password.  \nIncluding a character multiple times will up the chance of that particular character being selected when generating the password, eg. providing \"aaab\" will result in the character \"a\" appearing in the generated password three times more often than the character \"b\" on average.  \nEntropy is calculated based on the length of all unique characters included, so if generating a password from a subset of possible characters, the calculated entropy value will not be the same as one calculated using the original set.", placeholder="abcdefghijklmnopqrstuvwxyz", value="abcd")
        charset_size = len(set(charset))

        if charset == "":
            st.error("Please input at least one character.")
            input_valid = False
        else:
            input_valid = True

    if input_valid:
        if st.button("Generate Password", key="gen"):
            password = generate_password(length, charset)
            st.code(password, language=None)
            st.session_state["hash_input"] = password
            st.session_state["verify_pass"] = password
            entropy = calculate_entropy(password, charset_size)
            
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
    algorithm = st.radio("Algorithm", ["Argon2", "SHA-256", "bcrypt"], horizontal=True)

    if st.button("Hash Password", key="hash"):
        if password_input:
            hashed = hash_password(password_input, algorithm)
            st.code(hashed, language=None)
            st.success("✅ Password hashed successfully!")
            st.session_state["verify_hash"] = hashed
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
            if verify_hash.startswith("$argon2"):
                algo = "Argon2"
            elif verify_hash.startswith("b'"):
                algo = "bcrypt"
            else:
                algo = "SHA-256"
            is_valid = verify_password(verify_pass_input, verify_hash, algo)
            if is_valid:
                st.success("✅ Password matches the hash!")
            else:
                st.error("❌ Password does not match the hash.")
        else:
            st.warning("Please fill in both fields.")