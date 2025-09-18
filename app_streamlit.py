# app_streamlit.py
# Streamlit app for collecting Balochi sentences with MongoDB
# Features:
# - Guest contributions (limited per session)
# - User registration & login using streamlit-authenticator
# - Contributions are stored in MongoDB (users + sentences collections)
# - Leaderboard of top contributors
# - Admin export (download CSV/Excel) and moderation (approve/reject)

import streamlit as st
import pandas as pd
from datetime import datetime
import streamlit_authenticator as stauth
from pymongo import MongoClient
from bson.objectid import ObjectId

# -------------------- Config --------------------
MONGO_URI = st.secrets["MONGO_URI"]
DB_NAME = "balochi_db"

COOKIE_NAME = "balochi_app"
COOKIE_KEY = "balochi_secret_key_123"   # change in production
COOKIE_EXP_DAYS = 30

# -------------------- Helper: Robust password hashing --------------------
def hash_passwords(passwords):
    """
    Return a list of hashed passwords for the input list `passwords`.
    This function tries multiple ways to hash to be compatible with various
    streamlit-authenticator versions. If the library's Hasher isn't usable,
    it falls back to passlib bcrypt.
    """
    # try different Hasher locations / APIs
    HasherCls = None
    try:
        # try direct attribute from imported module
        HasherCls = getattr(stauth, "Hasher", None)
    except Exception:
        HasherCls = None

    if HasherCls is None:
        try:
            # try import from utilities module path
            from streamlit_authenticator.utilities.hasher import Hasher as HasherCls  # type: ignore
        except Exception:
            HasherCls = None

    if HasherCls is not None:
        # 1) try classmethod generate
        if hasattr(HasherCls, "generate"):
            try:
                # try calling as classmethod
                res = HasherCls.generate(passwords)  # type: ignore
                if isinstance(res, list):
                    return res
            except TypeError:
                # fallback: try creating instance
                try:
                    instance = HasherCls(passwords)  # type: ignore
                    if hasattr(instance, "generate"):
                        res = instance.generate()  # type: ignore
                        if isinstance(res, list):
                            return res
                except Exception:
                    pass
            except Exception:
                pass

        # 2) try hash_list
        if hasattr(HasherCls, "hash_list"):
            try:
                res = HasherCls.hash_list(passwords)  # type: ignore
                if isinstance(res, list):
                    return res
            except Exception:
                pass

        # 3) try hash (single) or hash_passwords
        if hasattr(HasherCls, "hash"):
            try:
                return [HasherCls.hash(p) for p in passwords]  # type: ignore
            except Exception:
                pass

        # 4) try hash_passwords (may expect a credentials dict; skip)
        # 5) no usable method found, fall through to passlib

    # fallback: use passlib bcrypt (ensure passlib[bcrypt] is installed)
    try:
        from passlib.hash import bcrypt  # type: ignore
        return [bcrypt.hash(p) for p in passwords]
    except Exception:
        # final fallback: use pbkdf2_hmac via hashlib (less ideal but works)
        import hashlib, os, binascii
        def pbkdf2_hash(pw: str) -> str:
            salt = os.urandom(16)
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
            return binascii.hexlify(salt + dk).decode()
        return [pbkdf2_hash(p) for p in passwords]


# -------------------- Database helpers --------------------
def get_db():
    client = MongoClient(MONGO_URI)
    return client[DB_NAME]

db = get_db()
users_col = db["users"]
sent_col = db["sentences"]

def get_users_df():
    users = list(users_col.find({}, {"_id": 1, "name": 1, "username": 1,
                                     "password_hash": 1, "contributions_count": 1,
                                     "is_admin": 1}))
    if len(users) == 0:
        # return empty dataframe with expected columns to avoid KeyErrors
        return pd.DataFrame(columns=["_id","name","username","password_hash","contributions_count","is_admin"])
    return pd.DataFrame(users)

def add_user(name, username, password_hash, is_admin=0):
    if users_col.find_one({"username": username}):
        return False
    users_col.insert_one({
        "name": name,
        "username": username,
        "password_hash": password_hash,
        "contributions_count": 0,
        "is_admin": is_admin
    })
    return True

def add_sentence(user_id, sentence, label, approved=0):
    ts = datetime.utcnow().isoformat()
    sent_col.insert_one({
        "user_id": str(user_id) if user_id else None,
        "sentence": sentence,
        "label": label,
        "timestamp": ts,
        "approved": approved
    })
    if user_id:
        try:
            users_col.update_one({"_id": ObjectId(user_id)}, {"$inc": {"contributions_count": 1}})
        except Exception:
            # if user_id is not a valid ObjectId, ignore
            pass

def get_sentences(only_approved=True, limit=100):
    q = {}
    if only_approved:
        q["approved"] = 1
    docs = list(sent_col.find(q).sort("_id", -1).limit(limit))
    # Join usernames
    for d in docs:
        if d.get("user_id"):
            try:
                u = users_col.find_one({"_id": ObjectId(d["user_id"])})
                d["username"] = u["username"] if u else "unknown"
            except Exception:
                d["username"] = "unknown"
        else:
            d["username"] = "guest"
    if len(docs) == 0:
        return pd.DataFrame(columns=["_id","user_id","sentence","label","timestamp","approved","username"])
    return pd.DataFrame(docs)

def get_leaderboard(limit=20):
    docs = list(users_col.find({}, {"username": 1, "contributions_count": 1})
                .sort("contributions_count", -1).limit(limit))
    if len(docs) == 0:
        return pd.DataFrame(columns=["username","contributions_count"])
    return pd.DataFrame(docs)

def export_data():
    df_users = get_users_df()
    df_sent = pd.DataFrame(list(sent_col.find()))
    return df_users, df_sent

# -------------------- Authentication helpers --------------------
def build_authenticator():
    users_df = get_users_df()

    # If no users exist, create default admin
    if users_df.shape[0] == 0:
        default_pass = "admin123"
        hashed = hash_passwords([default_pass])[0]
        add_user("Admin", "admin", hashed, is_admin=1)
        users_df = get_users_df()

    # Build credentials dict required by streamlit-authenticator
    credentials = {"usernames": {}}
    for _, row in users_df.iterrows():
        # ensure we have a valid hashed password in DB; field name 'password_hash'
        pw = row.get("password_hash", None) if isinstance(row, dict) else row["password_hash"]
        credentials["usernames"][row["username"]] = {
            "name": (row["name"] if pd.notna(row["name"]) else row["username"]),
            "password": pw
        }

    # Important: passwords stored in DB are already hashed, so disable auto_hash
    authenticator = stauth.Authenticate(
        credentials,
        COOKIE_NAME,
        COOKIE_KEY,
        COOKIE_EXP_DAYS,
        auto_hash=False
    )
    return authenticator, users_df

# -------------------- App UI --------------------
st.set_page_config(page_title="Balochi Sentence Collector", layout="centered")
authenticator, users_df = build_authenticator()

st.title("Balochi Sentence Collection")
st.write("Contribute Balochi sentences to build a sentiment dataset. You can contribute as a guest or create/login to track your contributions.")

# Sidebar
with st.sidebar:
    st.header("Account")
    choice = st.radio("Choose", ["Continue as Guest", "Login", "Register"])

    if choice == "Login":
        # Handle both old and new authenticator API styles
        login_result = authenticator.login(location="main")

        if login_result is not None:
            # old API: tuple unpacking
            try:
                name, authentication_status, username = login_result
            except Exception:
                name, authentication_status, username = None, None, None
        else:
            # new API: values stored in session_state
            name = st.session_state.get("name")
            username = st.session_state.get("username")
            authentication_status = st.session_state.get("authentication_status")

        if authentication_status:
            st.success(f"Welcome *{name}*")
            user_row = users_df[users_df["username"] == username]
            # convert ObjectId to str
            user_id = str(user_row["_id"].values[0])
            is_admin = int(user_row["is_admin"].values[0])
            st.session_state["user"] = {
                "name": name, "username": username, "id": user_id, "is_admin": is_admin
            }
            authenticator.logout(location="main")
        elif authentication_status == False:
            st.error("Username/password is incorrect")
        else:
            st.info("Please enter your username and password")

    elif choice == "Register":
        st.subheader("Register a new account")
        reg_name = st.text_input("Display name")
        reg_username = st.text_input("Choose a username")
        reg_password = st.text_input("Choose a password", type="password")
        if st.button("Create account"):
            if not reg_name or not reg_username or not reg_password:
                st.error("Please fill all fields")
            else:
                # create hashed password in a robust way
                hashed = hash_passwords([reg_password])[0]
                ok = add_user(reg_name, reg_username, hashed, is_admin=0)
                if ok:
                    st.success("Account created. Please go to Login.")
                else:
                    st.error("Username already exists")

    else:
        st.info("You can contribute as a guest. Register to track contributions and appear on the leaderboard.")

# Guest submission counter
if "guest_submissions" not in st.session_state:
    st.session_state["guest_submissions"] = 0

# Contribution form
st.subheader("Contribute a sentence")
with st.form("contribute"):
    sentence = st.text_area("Write a Balochi sentence", max_chars=300)
    label = st.selectbox("Sentiment", ["positive", "negative", "neutral"])
    submitted = st.form_submit_button("Submit")

if submitted:
    if "user" in st.session_state:
        uid = st.session_state["user"]["id"]
    else:
        uid = None

    if uid is None:
        if st.session_state["guest_submissions"] >= 10:
            st.warning("Guest submission limit reached. Please register for unlimited contributions.")
        else:
            add_sentence(None, sentence, label, approved=0)
            st.session_state["guest_submissions"] += 1
            st.success("Thank you! Your sentence has been submitted (awaiting approval).")
    else:
        add_sentence(uid, sentence, label, approved=1)
        st.success("Thanks — your sentence has been submitted and approved!")
        users_df = get_users_df()
        try:
            updated = users_df[users_df["_id"] == ObjectId(uid)]
            if not updated.empty:
                st.session_state["user"]["contributions"] = int(updated["contributions_count"].values[0])
        except Exception:
            pass

    # ✅ Clear fields & force refresh
    st.session_state["sentence_input"] = ""
    st.session_state["label_input"] = "positive"
    st.rerun()

# Show sentences
st.subheader("Recent approved sentences")
recent = get_sentences(only_approved=True, limit=50)
if recent.shape[0] == 0:
    st.info("No approved sentences yet.")
else:
    for _, row in recent.iterrows():
        st.markdown(f"**{row['username']}** — {row['label']}  \n> {row['sentence']}")

# Leaderboard
st.subheader("Leaderboard — Top contributors")
leader = get_leaderboard(limit=20)
if leader.shape[0] == 0:
    st.info("No contributors yet.")
else:
    st.table(leader[["username", "contributions_count"]])

# Admin panel
if "user" in st.session_state and st.session_state["user"].get("is_admin"):
    st.markdown("---")
    st.subheader("Admin panel")
    if st.button("Show pending"):
        pending = pd.DataFrame(list(sent_col.find({"approved": 0}).sort("_id", -1)))
        if pending.shape[0] == 0:
            st.info("No pending sentences.")
        else:
            st.dataframe(pending[["sentence", "label", "timestamp"]])
            selected = st.multiselect("Select IDs to approve", [str(x["_id"]) for x in pending.to_dict("records")])
            if st.button("Approve selected"):
                for sid in selected:
                    try:
                        sent_col.update_one({"_id": ObjectId(sid)}, {"$set": {"approved": 1}})
                    except Exception:
                        pass
                st.success("Selected sentences approved")
    if st.button("Export database as Excel"):
        users_df_export, sent_df_export = export_data()
        out_path = "balochi_export.xlsx"
        with pd.ExcelWriter(out_path) as writer:
            users_df_export.to_excel(writer, sheet_name="users", index=False)
            sent_df_export.to_excel(writer, sheet_name="sentences", index=False)
        with open(out_path, "rb") as f:
            st.download_button("Download Excel", f, file_name=out_path)

st.markdown("---")
# st.caption("Thank you for contributing to the Balochi language resources!")
st.caption("© 2025 Balochi Sentence Collector | Thank you for contributing to the Balochi language resources!")
