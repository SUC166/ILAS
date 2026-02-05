import streamlit as st
import pandas as pd
import os, re, time, secrets, hashlib
from datetime import datetime, timedelta, timezone
from streamlit_autorefresh import st_autorefresh

# ===== TIMEZONE (UTC +1 NIGERIA) =====
WAT = timezone(timedelta(hours=1))

TOKEN_LIFETIME = 20
DEPARTMENT = "EPE"

REP_USERNAME_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
REP_PASSWORD_HASH = "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1"

SESSIONS_FILE = "sessions.csv"
RECORDS_FILE = "records.csv"
CODES_FILE = "codes.csv"

SESSION_COLS = ["session_id", "type", "title", "status", "created_at", "department"]
RECORD_COLS = ["session_id", "name", "matric", "time", "device_id", "department"]
CODE_COLS = ["session_id", "code", "created_at"]

def load_csv(file, cols):
    return pd.read_csv(file, dtype=str) if os.path.exists(file) else pd.DataFrame(columns=cols)

def save_csv(df, file):
    df.to_csv(file, index=False)

def now():
    return datetime.now(WAT).strftime("%Y-%m-%d %H:%M:%S")

def normalize(t):
    return re.sub(r"\s+", " ", str(t).strip()).lower()

def sha256_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()

def device_id():
    if "device_id" not in st.session_state:
        raw = f"{time.time()}{secrets.token_hex()}"
        st.session_state.device_id = hashlib.sha256(raw.encode()).hexdigest()
    return st.session_state.device_id

def gen_code():
    return f"{secrets.randbelow(10000):04d}"

def session_title(att_type, course=""):
    base = datetime.now(WAT).strftime("%Y-%m-%d %H:%M")
    return f"{DEPARTMENT} - {course} {base}" if att_type == "Per Subject" else f"{DEPARTMENT} - Daily {base}"

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

def student_page():
    sessions = load_csv(SESSIONS_FILE, SESSION_COLS)
    active = sessions[sessions["status"] == "Active"]

    if active.empty:
        st.info("No active attendance.")
        return

    session = active.iloc[-1]
    sid = session["session_id"]

    if st.session_state.get("sid") != sid:
        st.title("Enter Attendance Code")
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

        records.loc[len(records)] = [sid, name, matric, now(), device_id(), DEPARTMENT]
        save_csv(records, RECORDS_FILE)
        st.success("Attendance recorded.")

def rep_login():
    st.title("Course Rep Login")
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
    st.title("EPE Course Rep Dashboard")

    sessions = load_csv(SESSIONS_FILE, SESSION_COLS)
    records = load_csv(RECORDS_FILE, RECORD_COLS)

    if not sessions[sessions["status"] == "Active"].empty:
        st.warning("⚠️ Attendance is ACTIVE. End it before starting a new one.")

    att = st.selectbox("Attendance Type", ["Daily", "Per Subject"])
    course = st.text_input("Course Code") if att == "Per Subject" else ""

    if st.button("Start Attendance") and sessions[sessions["status"] == "Active"].empty:
        sid = str(time.time())
        sessions.loc[len(sessions)] = [sid, att, session_title(att, course), "Active", now(), DEPARTMENT]
        save_csv(sessions, SESSIONS_FILE)
        write_new_code(sid)
        save_csv(pd.DataFrame(columns=RECORD_COLS), RECORDS_FILE)
        st.rerun()

    if sessions.empty:
        return

    sid = st.selectbox("Select Session", sessions["session_id"],
        format_func=lambda x: sessions[sessions["session_id"] == x]["title"].iloc[0])

    sess = sessions[sessions["session_id"] == sid].iloc[0]
    data = records[records["session_id"] == sid]

    st.write(f"Status: {sess['status']}")

    if sess["status"] == "Active":
        code, rem = rep_live_code(sid)
        st.markdown(f"## Live Code: `{code}`")
        st.caption(f"Refresh in {rem}s")

        if st.button("🛑 END ATTENDANCE"):
            sessions.loc[sessions["session_id"] == sid, "status"] = "Ended"
            save_csv(sessions, SESSIONS_FILE)
            st.rerun()

    st.divider()
    st.subheader("➕ Manual Entry")

    mn = st.text_input("Name (Manual)")
    mm = st.text_input("Matric (Manual)")

    if st.button("Add Manually"):
        if not re.fullmatch(r"\d{11}", mm):
            st.error("Invalid matric.")
        else:
            records.loc[len(records)] = [sid, mn, mm, now(), "MANUAL", DEPARTMENT]
            save_csv(records, RECORDS_FILE)
            st.rerun()

    st.divider()
    st.subheader("Attendance Records")

    view = data.reset_index(drop=True)
    view.insert(0, "S/N", range(1, len(view) + 1))
    st.dataframe(view, use_container_width=True)

    if not view.empty:
        sn = st.number_input("Select S/N", 1, len(view), 1)
        row = view.iloc[sn - 1]

        en = st.text_input("Edit Name", row["name"])
        em = st.text_input("Edit Matric", row["matric"])

        c1, c2 = st.columns(2)

        with c1:
            if st.button("✏️ Update"):
                records.loc[
                    (records["session_id"] == sid) & (records["matric"] == row["matric"]),
                    ["name", "matric"]
                ] = [en, em]
                save_csv(records, RECORDS_FILE)
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
                st.rerun()

    if sess["status"] == "Ended":
        out = view.copy()
        csv = out[["S/N", "department", "name", "matric", "time"]].to_csv(index=False).encode()
        st.download_button("📥 Download CSV", csv, file_name=f"{sess['title']}.csv")


def main():
    if "rep" not in st.session_state:
        st.session_state.rep = False

    page = st.sidebar.selectbox("Page", ["Student", "Course Rep"])
    student_page() if page == "Student" else (rep_dashboard() if st.session_state.rep else rep_login())

if __name__ == "__main__":
    main()

