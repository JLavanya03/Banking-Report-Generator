"""
banking_report.py

Single-file Streamlit app with:
- Authentication & roles: Developer (full), Admin (read/write), User (read)
- User management (Developer panel): list, create, delete, reset password
- Secure password hashing (bcrypt) and profile encryption (Fernet)
- Multi-sheet Excel upload (reads all sheets), auto-date detection
- Incremental upload merge: replace only months present in uploaded file
- Daily / Monthly / Yearly / Dashboard tabs with bar + pie charts
- Account search with timeline
- Local SQLite DBs: user_accounts.db and bank_reports.db
"""

import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime
import plotly.express as px
import os
from typing import Tuple, Optional, List
import json

# -----------------------
# Config / DB filenames
# -----------------------
USER_DB = "user_accounts.db"
REPORT_DB = "bank_reports.db"
PROFILE_KEY_FILE = "secret.key"  # fallback key file (local only)

# -----------------------
# App-wide constants
# -----------------------
STATUS_MAP = {
    "COMPLETED": "COMPLETED",
    "COMPLETE": "COMPLETED",
    "DONE": "COMPLETED",
    "FINISHED": "COMPLETED",
    "IN PROGRESS": "IN PROGRESS",
    "IN-PROGRESS": "IN PROGRESS",
    "INPROGRESS": "IN PROGRESS",
    "PENDING": "PENDING",
    "PEND": "PENDING",
    "WAITING": "PENDING",
}

STATUS_ORDER = ["COMPLETED", "IN PROGRESS", "PENDING"]
STATUS_COLORS = {"COMPLETED": "green", "IN PROGRESS": "orange", "PENDING": "red"}

# -----------------------
# Fernet key management
# -----------------------
def get_fernet() -> Fernet:
    """
    Use st.secrets['fernet_key'] if present (recommended on Streamlit Cloud).
    Otherwise read/create local secret.key file (convenient for local runs).
    """
    # 1) st.secrets
    try:
        if "fernet_key" in st.secrets:
            key = st.secrets["fernet_key"]
            if isinstance(key, bytes):
                return Fernet(key)
            if isinstance(key, str):
                keyb = key.encode()
                return Fernet(keyb)
    except Exception:
        # st.secrets may not be available outside Streamlit env or may fail
        pass

    # 2) environment variable
    env_key = os.getenv("STREAMLIT_FERNET_KEY")
    if env_key:
        try:
            return Fernet(env_key.encode())
        except Exception:
            pass

    # 3) fallback to local secret.key file
    if os.path.exists(PROFILE_KEY_FILE):
        with open(PROFILE_KEY_FILE, "rb") as f:
            key = f.read().strip()
        try:
            return Fernet(key)
        except Exception:
            # if invalid, regenerate
            key = Fernet.generate_key()
            with open(PROFILE_KEY_FILE, "wb") as f:
                f.write(key)
            return Fernet(key)
    else:
        key = Fernet.generate_key()
        with open(PROFILE_KEY_FILE, "wb") as f:
            f.write(key)
        return Fernet(key)

FERNET = get_fernet()

def encrypt_profile(profile: dict) -> bytes:
    # raw = pd.io.json.dumps(profile).encode("utf-8")
    raw = json.dumps(profile).encode("utf-8")
    return FERNET.encrypt(raw)

def decrypt_profile(token: Optional[bytes]) -> dict:
    if token is None:
        return {}
    try:
        if isinstance(token, memoryview):
            token = token.tobytes()
        if isinstance(token, str):
            token = token.encode()
        raw = FERNET.decrypt(token)
        return pd.io.json.loads(raw.decode("utf-8"))
    except (InvalidToken, Exception):
        return {"_profile_error": "decryption_failed"}

# -----------------------
# Database initialization
# -----------------------
def init_user_db():
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            profile BLOB
        )
    """)
    conn.commit()
    conn.close()

def init_report_db():
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bank_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_date TEXT NOT NULL,         -- ISO date YYYY-MM-DD
            account_number TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT,
            UNIQUE(report_date, account_number)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_report_date ON bank_reports (report_date)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_account ON bank_reports (account_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON bank_reports (status)")
    conn.commit()
    conn.close()

# -----------------------
# User management functions
# -----------------------
def user_exists() -> bool:
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    return count > 0

def create_user(username: str, password: str, role: str, profile: Optional[dict] = None) -> bool:
    if not username or not password:
        return False
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    profile_blob = encrypt_profile(profile or {"created_at": datetime.utcnow().isoformat(), "display_name": username})
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, role, profile) VALUES (?, ?, ?, ?)",
                    (username, hashed, role, profile_blob))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(username: str, password: str) -> Optional[dict]:
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role, profile FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    stored_hash, role, profile_blob = row
    try:
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            profile = decrypt_profile(profile_blob)
            return {"username": username, "role": role, "profile": profile}
    except Exception:
        return None
    return None

def list_users():
    conn = sqlite3.connect(USER_DB)
    df = pd.read_sql_query("SELECT username, role, profile FROM users ORDER BY role, username", conn)
    conn.close()
    # decrypt profiles
    df['profile'] = df['profile'].apply(lambda x: decrypt_profile(x))
    return df

def delete_user(username: str) -> bool:
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0

def reset_user_password(username: str, new_password: str) -> bool:
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = sqlite3.connect(USER_DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed, username))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0

# -----------------------
# Utility: column detection & normalization
# -----------------------
def detect_account_col(cols: List[str]) -> Optional[str]:
    candidates = ["account number", "account_number", "account", "acct", "acc_number"]
    for col in cols:
        if col.strip().lower() in candidates:
            return col
    # fuzzy search
    for col in cols:
        if "acct" in col.lower() or "account" in col.lower():
            return col
    return None

def detect_status_col(cols: List[str]) -> Optional[str]:
    candidates = ["status", "current_status", "acct_status", "state"]
    for col in cols:
        if col.strip().lower() in candidates:
            return col
    for col in cols:
        if "status" in col.lower() or "state" in col.lower():
            return col
    return None

def detect_date_col(cols: List[str], df: pd.DataFrame) -> Optional[str]:
    # First: exact-like "date" columns
    for col in cols:
        if "date" in col.lower():
            return col
    # Second: look for any column that parses as datetime for many rows
    for col in cols:
        try:
            sample = df[col].dropna().iloc[:20]
            parsed = pd.to_datetime(sample, errors='coerce')
            # if many parsed not-NaT consider it a date
            if parsed.notna().sum() >= max(1, len(sample)//2):
                return col
        except Exception:
            continue
    return None

def normalize_status(val: str) -> str:
    if pd.isna(val):
        return "PENDING"
    s = str(val).strip().upper()
    # Try direct map
    if s in STATUS_MAP:
        return STATUS_MAP[s]
    # try contains checks
    if "COMPLETE" in s or "DONE" in s or "FINISH" in s:
        return "COMPLETED"
    if "IN PROG" in s or "IN-PROG" in s or "INPROG" in s:
        return "IN PROGRESS"
    if "PEND" in s or "WAIT" in s:
        return "PENDING"
    # fallback
    return "PENDING"

# -----------------------
# Data ingestion and incremental merging
# -----------------------
def read_all_sheets(uploaded_file) -> pd.DataFrame:
    """
    Read all sheets from uploaded excel and concat into one DataFrame.
    """
    try:
        xls = pd.ExcelFile(uploaded_file)
        dfs = []
        for name in xls.sheet_names:
            try:
                df_sheet = xls.parse(name, dtype=str)
            except Exception:
                df_sheet = pd.read_excel(uploaded_file, sheet_name=name, dtype=str)
            dfs.append(df_sheet)
        if not dfs:
            return pd.DataFrame()
        combined = pd.concat(dfs, ignore_index=True, sort=False)
        return combined
    except Exception as e:
        raise

def prepare_upload_dataframe(raw_df: pd.DataFrame) -> Tuple[pd.DataFrame, str]:
    """
    Auto-detect columns, normalize, return DataFrame with columns:
    report_date (ISO YYYY-MM-DD), account_number, status (normalized), description (optional)
    Returns (prepared_df, detected_date_col_name)
    """
    df = raw_df.copy()
    df.columns = [str(c).strip() for c in df.columns]

    acct_col = detect_account_col(df.columns.tolist())
    status_col = detect_status_col(df.columns.tolist())
    date_col = detect_date_col(df.columns.tolist(), df)

    if acct_col is None:
        raise ValueError("Account number column not found.")
    if status_col is None:
        raise ValueError("Status column not found.")
    if date_col is None:
        raise ValueError("Date column not found or couldn't be detected.")

    # parse date column
    df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
    df = df.dropna(subset=[date_col, acct_col])
    # normalize columns
    out = pd.DataFrame()
    out['report_date'] = df[date_col].dt.strftime("%Y-%m-%d")
    out['account_number'] = df[acct_col].astype(str).str.strip()
    out['status'] = df[status_col].apply(normalize_status)
    if 'description' in [c.lower() for c in df.columns]:
        # find actual description column name (case-insensitive)
        desc_col = [c for c in df.columns if c.lower() == 'description'][0]
        out['description'] = df[desc_col].fillna("").astype(str)
    else:
        # try common synonyms
        desc_candidates = [c for c in df.columns if c.lower() in ('remarks', 'note', 'notes', 'desc')]
        if desc_candidates:
            out['description'] = df[desc_candidates[0]].fillna("").astype(str)
        else:
            out['description'] = ""
    # drop empty account numbers
    out = out[out['account_number'].notna() & (out['account_number'] != "")]
    # ensure uniqueness within the uploaded file: keep last occurrence per (report_date, account_number)
    out = out.drop_duplicates(subset=['report_date', 'account_number'], keep='last')
    return out, date_col

def merge_uploaded_dataframe(prep_df: pd.DataFrame) -> Tuple[int, int]:
    """
    Insert the prepared dataframe into DB, but first delete existing rows
    for the months present in the uploaded file. Returns (deleted_rows, inserted_rows)
    """
    if prep_df.empty:
        return 0, 0

    # months to replace: format YYYY-MM (first 7 chars of report_date)
    prep_df['yyyy_mm'] = prep_df['report_date'].str.slice(0, 7)
    months = prep_df['yyyy_mm'].unique().tolist()

    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    # Delete rows for these months
    # Using parameter substitution safely:
    placeholders = ",".join(["?"] * len(months))
    delete_query = f"""
        DELETE FROM bank_reports
        WHERE substr(report_date,1,7) IN ({placeholders})
    """
    cur.execute("BEGIN")
    try:
        cur.execute(delete_query, months)
        deleted = cur.rowcount
        # Insert new rows in bulk
        rows_to_insert = prep_df[['report_date', 'account_number', 'status', 'description']].to_records(index=False)
        insert_query = "INSERT OR REPLACE INTO bank_reports (report_date, account_number, status, description) VALUES (?, ?, ?, ?)"
        cur.executemany(insert_query, list(rows_to_insert))
        inserted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise
    conn.close()
    return deleted, inserted

# -----------------------
# Data load and caching
# -----------------------
@st.cache_data(ttl=120)
def load_all_reports() -> pd.DataFrame:
    """
    Load all report rows from DB and add Day/Month/Year columns.
    No unhashable params passed.
    """
    conn = sqlite3.connect(REPORT_DB)
    try:
        df = pd.read_sql_query("SELECT report_date, account_number, status, description FROM bank_reports", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    if df.empty:
        return df
    df['report_date'] = pd.to_datetime(df['report_date'], errors='coerce')
    df = df.dropna(subset=['report_date'])
    df['Day'] = df['report_date'].dt.date
    df['Month'] = df['report_date'].dt.strftime("%Y-%m")
    df['Year'] = df['report_date'].dt.year
    # ensure status normalized (in case)
    df['status'] = df['status'].apply(normalize_status)
    return df

# -----------------------
# Visualization helpers
# -----------------------
def plot_bar_pie_from_series(series: pd.Series, title: str = ""):
    """
    series: index=status label, value=count
    """
    if series.empty or series.sum() == 0:
        st.info("No data to display for this selection.")
        return
    df = series.reset_index()
    df.columns = ['Status', 'Count']
    # ensure ordering
    df['Status'] = pd.Categorical(df['Status'], categories=STATUS_ORDER, ordered=True)
    df = df.sort_values('Status')
    col1, col2 = st.columns([2, 1])
    with col1:
        fig = px.bar(df, x='Status', y='Count', title=title, color='Status', color_discrete_map=STATUS_COLORS)
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        fig2 = px.pie(df, names='Status', values='Count', title=f"{title} - Proportions", color='Status', color_discrete_map=STATUS_COLORS)
        st.plotly_chart(fig2, use_container_width=True)

# -----------------------
# UI: Authentication & User Management
# -----------------------
def signup_ui():
    st.subheader("Create a new account")
    username = st.text_input("Username", key="su_user")
    password = st.text_input("Password", type="password", key="su_pass")
    role = st.selectbox("Role", ["Developer", "Admin", "User"], key="su_role")
    if st.button("Create account"):
        if not username or not password:
            st.error("Username and password required.")
            return
        ok = create_user(username, password, role)
        if ok:
            st.success(f"Account '{username}' created. You can now log in.")
        else:
            st.warning("Username already exists.")

def login_ui():
    st.subheader("Login")
    username = st.text_input("Username", key="li_user")
    password = st.text_input("Password", type="password", key="li_pass")
    if st.button("Login"):
        user = authenticate_user(username, password)
        if user is None:
            st.error("Invalid credentials.")
        else:
            st.session_state['authenticated'] = True
            st.session_state['user'] = user
            st.rerun()

def developer_panel_sidebar():
    st.sidebar.markdown("---")
    st.sidebar.subheader("Developer: User Management")
    with st.sidebar.expander("Manage users"):
        users_df = list_users()
        if users_df.empty:
            st.write("No users found.")
        else:
            # show username and role and profile display_name if present
            display_df = users_df.copy()
            display_df['display_name'] = display_df['profile'].apply(lambda p: p.get('display_name', ''))
            st.dataframe(display_df[['username', 'role', 'display_name']], use_container_width=True)

        st.write("### Add user")
        nu = st.text_input("New username", key="dev_new_user")
        npw = st.text_input("New password", key="dev_new_pass", type="password")
        nrole = st.selectbox("Role", ["Developer", "Admin", "User"], key="dev_new_role")
        if st.button("Add user", key="dev_add"):
            if not nu or not npw:
                st.error("Provide username and password.")
            else:
                ok = create_user(nu, npw, nrole, profile={"display_name": nu, "created_at": datetime.utcnow().isoformat()})
                if ok:
                    st.success("User created.")
                    st.rerun()
                else:
                    st.warning("Username exists.")

        st.write("### Delete user")
        existing = [u for u in list_users()['username'].tolist() if u != st.session_state.get('user', {}).get('username')]
        if existing:
            del_user = st.selectbox("Select user to delete", existing, key="dev_del_select")
            if st.button("Delete user", key="dev_del"):
                deleted = delete_user(del_user)
                if deleted:
                    st.success(f"Deleted {del_user}")
                    st.rerun()
                else:
                    st.error("Delete failed.")
        else:
            st.caption("No deletable users found (cannot delete yourself).")

        st.write("### Reset password")
        all_users = list_users()['username'].tolist()
        if all_users:
            tgt = st.selectbox("Select user", all_users, key="dev_rst_select")
            newpw = st.text_input("New password", type="password", key="dev_rst_pw")
            if st.button("Reset password", key="dev_rst_btn"):
                if not newpw:
                    st.error("Enter a new password.")
                else:
                    ok = reset_user_password(tgt, newpw)
                    if ok:
                        st.success("Password updated.")
                    else:
                        st.error("Failed to update password.")

# -----------------------
# UI: Upload & merge (multi-sheet)
# -----------------------
def upload_ui():
    st.sidebar.subheader("Upload Excel")
    uploaded = st.sidebar.file_uploader("Upload .xlsx or .xls (multi-sheet supported)", type=["xlsx", "xls"])
    if not uploaded:
        return
    try:
        raw = read_all_sheets(uploaded)
    except Exception as e:
        st.sidebar.error(f"Failed to read Excel: {e}")
        return

    try:
        prep, detected_date_col = prepare_upload_dataframe(raw)
    except Exception as e:
        st.sidebar.error(f"Failed to prepare data: {e}")
        return

    if prep.empty:
        st.sidebar.warning("No valid rows found in uploaded file after parsing.")
        return

    # Merge - delete existing months, insert new rows
    try:
        deleted, inserted = merge_uploaded_dataframe(prep)
        # Clear cache so that new data is shown
        load_all_reports.clear()
        st.session_state['db_updated'] = True
        st.sidebar.success(f"Imported {inserted} rows; replaced months: {', '.join(prep['report_date'].str.slice(0,7).unique())}")
    except Exception as e:
        st.sidebar.error(f"DB merge failed: {e}")

# -----------------------
# UI: Dashboards & Reports
# -----------------------
def show_dashboard(df: pd.DataFrame):
    st.header("Dashboard — Overview")
    overall = df['status'].value_counts().reindex(STATUS_ORDER, fill_value=0)
    plot_bar_pie_from_series(overall, "Overall Status (All Time)")

def show_daily(df: pd.DataFrame):
    st.header("Daily Reports")
    dates = sorted(df['Day'].unique())
    if not dates:
        st.info("No daily data available.")
        return
    sel = st.selectbox("Select date", dates, index=len(dates)-1)
    sub = df[df['Day'] == sel]
    series = sub['status'].value_counts().reindex(STATUS_ORDER, fill_value=0)
    plot_bar_pie_from_series(series, f"Status on {sel}")

def show_monthly(df: pd.DataFrame):
    st.header("Monthly Reports")
    months = sorted(df['Month'].unique())
    if not months:
        st.info("No monthly data available.")
        return
    sel = st.selectbox("Select month (YYYY-MM)", months, index=len(months)-1)
    sub = df[df['Month'] == sel]
    series = sub['status'].value_counts().reindex(STATUS_ORDER, fill_value=0)
    plot_bar_pie_from_series(series, f"Status in {sel}")

def show_yearly(df: pd.DataFrame):
    st.header("Yearly Reports")
    years = sorted(df['Year'].unique())
    if not years:
        st.info("No yearly data available.")
        return
    sel = st.selectbox("Select year", years, index=len(years)-1)
    sub = df[df['Year'] == sel]
    series = sub['status'].value_counts().reindex(STATUS_ORDER, fill_value=0)
    plot_bar_pie_from_series(series, f"Status in {sel}")

def show_account_search(df: pd.DataFrame):
    st.header("Account Search")
    q = st.text_input("Enter account number (partial match allowed)")
    if not q:
        st.info("Enter account number to view history.")
        return
    # matches = df[df['account_number'].str.contains(q, case=False, na=False)]['account_number'].unique().tolist()
    matches = df[df['account_number'].astype(str).str.contains(str(q), case=False, na=False)]['account_number'].unique().tolist()
    if not matches:
        st.warning("No matching accounts found.")
        return
    sel = st.selectbox("Matching accounts", matches)
    history = df[df['account_number'] == sel].sort_values('report_date')
    st.subheader(f"History for {sel}")
    st.dataframe(history[['report_date', 'status', 'description']].rename(columns={'report_date':'Date'}))
    # timeline
    if not history.empty:
        mapping = {s: i for i, s in enumerate(STATUS_ORDER)}
        history['y'] = history['status'].map(mapping)
        fig = px.scatter(history, x='report_date', y='y', color='status', text='status',
                         labels={'y':'Status', 'report_date':'Date'}, title=f"Timeline for {sel}",
                         color_discrete_map=STATUS_COLORS)
        fig.update_yaxes(tickmode='array', tickvals=list(mapping.values()), ticktext=STATUS_ORDER)
        st.plotly_chart(fig, use_container_width=True)

# -----------------------
# Main app layout & flow
# -----------------------
def main():
    st.set_page_config(page_title="Banking Reports", layout="wide")
    # init DBs
    init_user_db()
    init_report_db()

    st.sidebar.title("Banking Reports")
    # If no users exist, show setup flow on sidebar
    if not user_exists():
        st.sidebar.warning("No users found. Create a Developer account to continue.")
        st.sidebar.subheader("Create initial Developer account")
        c_user = st.sidebar.text_input("Developer username", key="init_user")
        c_pass = st.sidebar.text_input("Developer password", type="password", key="init_pass")
        if st.sidebar.button("Create Developer"):
            if not c_user or not c_pass:
                st.sidebar.error("Provide username & password.")
            else:
                ok = create_user(c_user, c_pass, "Developer", profile={"display_name": c_user, "created_at": datetime.utcnow().isoformat()})
                if ok:
                    st.sidebar.success("Developer account created. Please log in below.")
                    st.rerun()
                else:
                    st.sidebar.error("Failed to create user (maybe exists).")
        st.stop()



    # Authentication UI
    if "authenticated" not in st.session_state or not st.session_state.get('authenticated'):
        st.sidebar.subheader("Account")
        auth_action = st.sidebar.radio("Action", ["Login", "Sign up"])
        if auth_action == "Sign up":
            signup_ui()
            st.sidebar.info("Note: only Developers can manage users after signup.")
        else:
            login_ui()
        st.stop()

    # At this point, user is authenticated
    user = st.session_state.get('user', {})
    username = user.get('username')
    role = user.get('role', 'User')
    display_name = user.get('profile', {}).get('display_name', username)

    st.sidebar.markdown(f"**Logged in:** {display_name} ({role})")
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    # Developer panel
    if role == "Developer":
        developer_panel_sidebar()

    # Upload (Developer & Admin)
    if role in ("Developer", "Admin"):
        upload_ui()
    else:
        st.sidebar.info("View-only: contact Admin/Developer to upload data.")

    # Load data from DB (cached)
    df = load_all_reports()

    # show main navigation
    st.sidebar.markdown("---")
    tabs = ["Dashboard", "Daily", "Monthly", "Yearly", "Account Search"]
    choice = st.sidebar.radio("Navigate", tabs)

    if df.empty:
        st.info("No data available. Upload Excel file (multi-sheet supported) in the sidebar.")
        return

    if choice == "Dashboard":
        show_dashboard(df)
    elif choice == "Daily":
        show_daily(df)
    elif choice == "Monthly":
        show_monthly(df)
    elif choice == "Yearly":
        show_yearly(df)
    elif choice == "Account Search":
        show_account_search(df)

if __name__ == "__main__":
    main()
