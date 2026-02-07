import streamlit as st
import requests
import base64
import pandas as pd
import os
import re
import time
import secrets
import hashlib

from datetime import datetime, timedelta, timezone
from streamlit_autorefresh import st_autorefresh
from streamlit_cookies_manager import CookieManager


# ================= LEVEL CONFIG =================
LEVEL_NAME = "200LVL"  # CHANGE PER FILE


if "rep" not in st.session_state:
    st.session_state.rep = False

cookies = CookieManager()


# ===== TIMEZONE (UTC +1 NIGERIA) =====
WAT = timezone(timedelta(hours=1))


TOKEN_LIFETIME = 20
DEPARTMENT = "EPE"


# ===== REP AUTH (DO NOT RENAME — CAMP UPDATES THESE) =====
REP_NAME = "55c8079ac96c6a4f6a94e3460c79e4006d62374cce6e9fc8b281938a3abc7627"
REP_PASS = "55c8079ac96c6a4f6a94e3460c79e4006d62374cce6e9fc8b281938a3abc7627"

REP_USERNAME_HASH = REP_NAME
REP_PASSWORD_HASH = REP_PASS


SESSIONS_FILE = f"sessions_{LEVEL_NAME}.csv"
RECORDS_FILE = f"records_{LEVEL_NAME}.csv"
CODES_FILE = f"codes_{LEVEL_NAME}.csv"


SESSION_COLS = [
    "session_id", "type", "title", "status",
    "date", "created_at", "department", "course"
]

RECORD_COLS = [
    "session_id", "name", "matric",
    "time", "device_id", "department"
]

CODE_COLS = ["session_id", "code", "created_at"]


def load_csv(file, cols):
    if os.path.exists(file):
        return pd.read_csv(file, dtype=str)
    return pd.DataFrame(columns=cols)


def save_csv(df, file):
    df.to_csv(file, index=False)


def now():
    return datetime.now(WAT).strftime("%Y-%m-%d %H:%M:%S")


def normalize(t):
    return re.sub(r"\s+", " ", str(t).strip()).lower()


def sha256_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()


def device_id():
    # If already cached in session, reuse instantly
    if "ilas_device_id_cached" in st.session_state:
        return st.session_state.ilas_device_id_cached

    # If cookie exists, reuse it
    if "ilas_device_id" in cookies:
        st.session_state.ilas_device_id_cached = cookies["ilas_device_id"]
        return cookies["ilas_device_id"]

    # Otherwise generate ONCE
    raw = f"{time.time()}{secrets.token_hex(16)}"
    did = hashlib.sha256(raw.encode()).hexdigest()

    cookies["ilas_device_id"] = did
    st.session_state.ilas_device_id_cached = did

    return did


    return cookies["ilas_device_id"]



def gen_code():
    return f"{secrets.randbelow(10000):04d}"


def session_title(att_type, course=""):
    base = datetime.now(WAT).strftime("%Y-%m-%d %H:%M")
    if att_type == "Per Subject":
        return f"{DEPARTMENT} {LEVEL_NAME} - {course} {base}"
    return f"{DEPARTMENT} {LEVEL_NAME} - Daily {base}"


def write_new_code(sid):
    codes = load_csv(CODES_FILE, CODE_COLS)
    codes.loc[len(codes)] = [sid, gen_code(), now()]
    save_csv(codes, CODES_FILE)
    return codes.iloc[-1]["code"]


def latest_code(sid):
    codes = load_csv(CODES_FILE, CODE_COLS)
    c = codes[codes["session_id"] == sid]
    if c.empty:
        return None
    c["created_at"] = pd.to_datetime(c["created_at"])
    return c.sort_values("created_at").iloc[-1]


def rep_live_code(sid):
    c = latest_code(sid)
    if c is None:
        return write_new_code(sid), TOKEN_LIFETIME

    age = (datetime.now(WAT).replace(tzinfo=None) - c["created_at"]).total_seconds()
    if age >= TOKEN_LIFETIME:
        return write_new_code(sid), TOKEN_LIFETIME

    return c["code"], int(TOKEN_LIFETIME - age)


def code_valid(sid, entered):
    c = latest_code(sid)
    if c is None:
        return False

    age = (datetime.now(WAT).replace(tzinfo=None) - c["created_at"]).total_seconds()
    return str(entered).zfill(4) == str(c["code"]).zfill(4) and age <= TOKEN_LIFETIME


def attendance_filename(sess):
    date = sess["date"]

    course_raw = sess["course"]
    course = (
        str(course_raw).replace(" ", "")
        if pd.notna(course_raw) and str(course_raw).strip()
        else "Daily"
    )

    start = sess["created_at"][11:16].replace(":", "-")

    return f"{DEPARTMENT}_{LEVEL_NAME}_{course}_{date}_{start}.csv"



def upload_attendance_to_lecturer_dashboard(date, filename, content):
    token = st.secrets["LECTURER_DASHBOARD_PAT"]
    repo = st.secrets["LECTURER_DASHBOARD_REPO"]

    path = f"attendance/{date}/{filename}"
    url = f"https://api.github.com/repos/{repo}/contents/{path}"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    payload = {
        "message": f"Add attendance {filename}",
        "content": base64.b64encode(content).decode()
    }

    r = requests.put(url, json=payload, headers=headers)
    return r.status_code in (200, 201)


def student_page():
    sessions = load_csv(SESSIONS_FILE, SESSION_COLS)
    active = sessions[sessions["status"] == "Active"]

    if active.empty:
        st.info("No active attendance.")
        return

    session = active.iloc[-1]
    sid = session["session_id"]

    if st.session_state.get("sid") != sid:
        st.title(f"Enter Attendance Code — {LEVEL_NAME}")
        code = st.text_input("4-Digit Code")

        if st.button("Continue"):
            if not code_valid(sid, code):
                st.error("Invalid or expired code.")
                return
            st.session_state.sid = sid
            st.rerun()
        return

    st.subheader("Attendance Form")
    name = st.text_input("Full Name")
    matric = st.text_input("Matric Number")

    if st.button("Submit"):
        if not re.fullmatch(r"\d{11}", matric):
            st.error("Invalid matric.")
            return

        records = load_csv(RECORDS_FILE, RECORD_COLS)
        srec = records[records["session_id"] == sid]

        if normalize(name) in srec["name"].apply(normalize).values:
            st.error("Name already used.")
            return
        if matric in srec["matric"].values:
            st.error("Matric already used.")
            return
        if device_id() in srec["device_id"].values:
            st.error("One entry per device.")
            return

        records.loc[len(records)] = [
            sid, name, matric, now(), device_id(), DEPARTMENT
        ]
        save_csv(records, RECORDS_FILE)
        st.success("Attendance recorded.")


def rep_login():
    st.title(f"Course Rep Login — {LEVEL_NAME}")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        if sha256_hash(u) == REP_USERNAME_HASH and sha256_hash(p) == REP_PASSWORD_HASH:
            st.session_state.rep = True
            st.rerun()
        else:
            st.error("Invalid credentials.")


def rep_dashboard():
    st_autorefresh(interval=1000, key="r")
    st.title(f"Course Rep Dashboard — {LEVEL_NAME}")

    sessions = load_csv(SESSIONS_FILE, SESSION_COLS)
    records = load_csv(RECORDS_FILE, RECORD_COLS)

    if not sessions[sessions["status"] == "Active"].empty:
        st.warning("⚠️ Attendance is ACTIVE. End it before starting another.")

    att = st.selectbox("Attendance Type", ["Daily", "Per Subject"])
    course = st.text_input("Course Code") if att == "Per Subject" else ""

    if st.button("Start Attendance") and sessions[sessions["status"] == "Active"].empty:
        sid = str(time.time())
        today = datetime.now(WAT).strftime("%Y-%m-%d")

        sessions.loc[len(sessions)] = [
            sid, att, session_title(att, course), "Active",
            today, now(), DEPARTMENT, course
        ]
        save_csv(sessions, SESSIONS_FILE)
        write_new_code(sid)
        save_csv(pd.DataFrame(columns=RECORD_COLS), RECORDS_FILE)
        st.rerun()

    if sessions.empty:
        return

    sid = st.selectbox(
        "Select Session",
        sessions["session_id"],
        format_func=lambda x: sessions[sessions["session_id"] == x]["title"].iloc[0]
    )

    sess = sessions[sessions["session_id"] == sid].iloc[0]
    data = records[records["session_id"] == sid]

    st.write(f"Status: {sess['status']}")

    # ===== ACTIVE SESSION =====
    if sess["status"] == "Active":
        code, rem = rep_live_code(sid)
        st.markdown(f"## Live Code: `{code}`")
        st.caption(f"Refresh in {rem}s")

        if st.button("🛑 END ATTENDANCE"):
            sessions.loc[sessions["session_id"] == sid, "status"] = "Ended"
            save_csv(sessions, SESSIONS_FILE)

            out = data.copy().reset_index(drop=True)
            out.insert(0, "S/N", range(1, len(out) + 1))

            csv_bytes = out[
                ["S/N", "department", "name", "matric", "time"]
            ].to_csv(index=False).encode()

            filename = attendance_filename(sess)

            success = upload_attendance_to_lecturer_dashboard(
                sess["date"], filename, csv_bytes
            )

            if not success:
                st.error("❌ Failed to publish attendance.")
                return

            st.success("✅ Attendance locked & published")
            st.rerun()

    # ===== MANUAL ENTRY =====
    if sess["status"] == "Active":
        st.divider()
        st.subheader("➕ Manual Entry")

        mn = st.text_input("Name (Manual)")
        mm = st.text_input("Matric (Manual)")

        if st.button("Add Manually"):
            if not re.fullmatch(r"\d{11}", mm):
                st.error("Invalid matric.")
            else:
                records.loc[len(records)] = [
                    sid, mn, mm, now(), "MANUAL", DEPARTMENT
                ]
                save_csv(records, RECORDS_FILE)
                st.rerun()

    # ===== RECORDS VIEW =====
    st.divider()
    st.subheader("Attendance Records")

    view = data.reset_index(drop=True)
    view.insert(0, "S/N", range(1, len(view) + 1))
    st.dataframe(view, use_container_width=True)

    # ===== EDIT / DELETE =====
    if sess["status"] == "Active" and not view.empty:
        st.divider()
        st.subheader("✏️ Edit / 🗑️ Delete Entry")

        sn = st.number_input("Select S/N", 1, len(view), 1)
        row = view.iloc[sn - 1]

        en = st.text_input("Edit Name", row["name"])
        em = st.text_input("Edit Matric", row["matric"])

        c1, c2 = st.columns(2)

        with c1:
            if st.button("✏️ Update"):
                records.loc[
                    (records["session_id"] == sid) &
                    (records["matric"] == row["matric"]),
                    ["name", "matric"]
                ] = [en, em]
                save_csv(records, RECORDS_FILE)
                st.success("Updated successfully")
                st.rerun()

        with c2:
            if st.button("🗑️ Delete"):
                records = records.drop(
                    records[
                        (records["session_id"] == sid) &
                        (records["matric"] == row["matric"])
                    ].index
                )
                save_csv(records, RECORDS_FILE)
                st.success("Deleted successfully")
                st.rerun()


def main():
    page = st.sidebar.selectbox("Page", ["Student", "Course Rep"])

    if page == "Student":
        student_page()
    else:
        rep_dashboard() if st.session_state.rep else rep_login()

    # ================== FOOTER ==================
    st.divider()
    st.caption(
        "❤️ Made with love by EPE2025/26. FODC. "
        "Support: wa.me/2348118429150"
    )


if __name__ == "__main__":
    main()
