import streamlit as st
import requests
import base64
import hashlib
import re
import json
from datetime import datetime

# ---------------- CONFIG ----------------
st.set_page_config(page_title="CAMP", layout="centered")

ILAS_PATHS = {
    "100LVL": "ilas100.py",
    "200LVL": "ilas200.py",
    "300LVL": "ilas300.py",
    "400LVL": "ilas400.py",
    "500LVL": "ilas500.py",
    "600LVL": "ilas600.py",
}

AUDIT_FILE = "audit_logs.json"

# ---------------- AUTH CONFIG ----------------
ADVISOR_USER_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
ADVISOR_PASS_HASH = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

# ---------------- HELPERS ----------------
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def github_headers():
    return {
        "Authorization": f"token {st.secrets['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }

# ---------------- AUTH ----------------
def login_page():
    st.title("🎓 CAMP Advisor Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if (
            sha256_hash(username) == ADVISOR_USER_HASH
            and sha256_hash(password) == ADVISOR_PASS_HASH
        ):
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Invalid credentials")

def logout():
    st.session_state.clear()
    st.rerun()

# ---------------- GITHUB OPS ----------------
def fetch_ilas_file(level):
    repo = st.secrets["GITHUB_REPO"]
    file_path = ILAS_PATHS[level]

    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    r = requests.get(url, headers=github_headers())

    if r.status_code != 200:
        st.error(f"Failed to fetch {level} ILAS")
        st.stop()

    data = r.json()
    code = base64.b64decode(data["content"]).decode()
    return code, data["sha"]

def update_rep_credentials(code, user_hash, pass_hash):
    code = re.sub(
        r'REP_NAME\s*=\s*".*?"',
        f'REP_NAME = "{user_hash}"',
        code
    )
    code = re.sub(
        r'REP_PASS\s*=\s*".*?"',
        f'REP_PASS = "{pass_hash}"',
        code
    )
    return code

def push_ilas_file(updated_code, sha, level):
    repo = st.secrets["GITHUB_REPO"]
    file_path = ILAS_PATHS[level]

    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"

    encoded = base64.b64encode(updated_code.encode()).decode()

    payload = {
        "message": f"CAMP: Update {level} course rep credentials",
        "content": encoded,
        "sha": sha
    }

    r = requests.put(url, headers=github_headers(), json=payload)
    return r.status_code in (200, 201)

# ---------------- AUDIT LOGGING ----------------
def fetch_audit_logs():
    repo = st.secrets["GITHUB_REPO"]
    url = f"https://api.github.com/repos/{repo}/contents/{AUDIT_FILE}"

    r = requests.get(url, headers=github_headers())
    if r.status_code != 200:
        return [], None

    data = r.json()
    logs = json.loads(base64.b64decode(data["content"]).decode())
    return logs, data["sha"]

def push_audit_logs(logs, sha):
    repo = st.secrets["GITHUB_REPO"]
    url = f"https://api.github.com/repos/{repo}/contents/{AUDIT_FILE}"

    encoded = base64.b64encode(json.dumps(logs, indent=2).encode()).decode()

    payload = {
        "message": "CAMP: Append audit log",
        "content": encoded,
        "sha": sha
    }

    requests.put(url, headers=github_headers(), json=payload)

def log_audit(level, status):
    logs, sha = fetch_audit_logs()

    entry = {
        "level": level,
        "action": "UPDATED_REP_CREDENTIALS",
        "timestamp": datetime.utcnow().isoformat(),
        "status": status
    }

    logs.append(entry)
    push_audit_logs(logs, sha)

# ---------------- DASHBOARD ----------------
def camp_dashboard():
    st.title("🛠️ CAMP Dashboard")
    st.caption("Course Advisory & Management Platform")

    st.divider()

    selected_level = st.selectbox(
        "Select Level",
        list(ILAS_PATHS.keys())
    )

    rep_user = st.text_input(f"New Course Rep Username ({selected_level})")
    rep_pass = st.text_input(f"New Course Rep Password ({selected_level})", type="password")

    if st.button("🚀 Update Course Rep"):
        if not rep_user or not rep_pass:
            st.error("All fields are required")
            return

        try:
            code, sha = fetch_ilas_file(selected_level)

            updated = update_rep_credentials(
                code,
                sha256_hash(rep_user),
                sha256_hash(rep_pass)
            )

            ok = push_ilas_file(updated, sha, selected_level)

            if ok:
                log_audit(selected_level, "SUCCESS")
                st.success(f"✅ {selected_level} rep credentials updated")
            else:
                log_audit(selected_level, "FAILED")
                st.error("❌ Update failed")

        except:
            log_audit(selected_level, "ERROR")
            st.error("Unexpected error occurred")

# ---------------- MAIN ----------------
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    if st.sidebar.button("Logout"):
        logout()

    camp_dashboard()

if __name__ == "__main__":
    main()
