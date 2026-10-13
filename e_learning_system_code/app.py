# -*- coding: utf-8 -*-
"""
E-Learning — 3-role edition
SuperAdmin / Teacher / Student
"""
import os, uuid, hashlib, secrets
from datetime import datetime, timedelta
from flask import get_flashed_messages
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify)

from werkzeug.utils import secure_filename
import os as _os

UPLOAD_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "uploads")
_os.makedirs(UPLOAD_DIR, exist_ok=True)

if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line=line.strip()
            if line and "=" in line and not line.startswith("#"):
                k,v = line.split("=",1)
                os.environ.setdefault(k.strip(), v.strip())

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

PASSWORD_PEPPER = os.environ.get("PASSWORD_PEPPER", "pepper-2024")
DELETE_GRACE_DAYS = 7

# ─── Security constants ───
PBKDF2_ITERATIONS = 200_000      # recommended minimum for 2024+
PBKDF2_ALGO = "sha256"
SALT_BYTES = 16                  # 32 hex chars per-user salt
USER_ID_BYTES = 6                # 6 bytes → 12 uppercase hex chars


# =====================================================================
# SECURITY HELPERS
# =====================================================================
def hash_password(password, salt=None):
    """
    Hash a password with PBKDF2-HMAC-SHA256 + per-user random salt + pepper.
    Returns a self-contained string: pbkdf2$<iterations>$<salt>$<hash>
    """
    if password is None:
        password = ""
    if salt is None:
        salt = secrets.token_hex(SALT_BYTES)
    combined = (PASSWORD_PEPPER + str(password)).encode("utf-8")
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO,
        combined,
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return "pbkdf2${}${}${}".format(PBKDF2_ITERATIONS, salt, derived.hex())


def verify_password(password, stored_hash):
    """
    Constant-time verification of a password against a stored PBKDF2 hash.
    Also supports legacy SHA-256 hashes (64 hex chars) for backward compat.
    """
    if not stored_hash:
        return False
    if password is None:
        password = ""

    # ─── Legacy SHA-256 (for old accounts during transition) ───
    if len(stored_hash) == 64 and "$" not in stored_hash:
        legacy = hashlib.sha256(
            (PASSWORD_PEPPER + str(password)).encode()
        ).hexdigest()
        return secrets.compare_digest(legacy, stored_hash)

    # ─── PBKDF2 format: pbkdf2$iterations$salt$hash ───
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected = parts[3]
    except (ValueError, IndexError):
        return False

    combined = (PASSWORD_PEPPER + str(password)).encode("utf-8")
    actual = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO,
        combined,
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return secrets.compare_digest(actual, expected)


def generate_user_id():
    """
    12-character uppercase hex ID (16^12 = 2.8 trillion combinations).
    Cryptographically random using secrets module.
    """
    return secrets.token_hex(USER_ID_BYTES).upper()

def generate_temp_password():
    """Format: TMP-XXXXXX (e.g. TMP-A1B2C3)"""
    return "TMP-" + secrets.token_hex(3).upper()

# =====================================================================
# STORAGE
# =====================================================================
users = []              # User objects
studies = []            # dicts
quiz_results = []       # dicts
attendance = []         # dicts
notifications = []      # dicts
connections = []        # dicts
activities_list = []
temp_question = []

# =====================================================================
# HELPERS
# =====================================================================
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def today_str():
    return datetime.now().strftime("%Y-%m-%d")


def now_dt():
    return datetime.now()


def find_user_by_username(u):
    if not u:
        return None
    for x in users:
        if x.username.lower() == u.lower():
            return x
    return None


def find_user_by_id(uid):
    for x in users:
        if x.id == uid:
            return x
    return None


def find_study(stid):
    for s in studies:
        if s["id"] == stid:
            return s
    return None


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return find_user_by_id(uid)


def calc_medal(pct):
    if pct >= 90:
        return "Gold"
    if pct >= 75:
        return "Silver"
    if pct >= 60:
        return "Bronze"
    return None


def build_leaderboard():
    rows = []
    for st in users:
        if st.role != "Student" or not st.is_active():
            continue
        st_results = [r for r in quiz_results if r["student_id"] == st.id]
        total = sum(r["score"] for r in st_results)
        medals = [r["medal"] for r in st_results if r.get("medal")]
        rows.append({
            "id": st.id, "username": st.username, "full_name": st.full_name,
            "points": total,
            "gold": medals.count("Gold"),
            "silver": medals.count("Silver"),
            "bronze": medals.count("Bronze"),
            "medals": medals, "attempts": len(st_results),
        })
    rows.sort(key=lambda r: (-r["points"], r["username"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows


def role_home(role):
    return {"SuperAdmin": "super_admin_page",
            "Teacher": "teacher_page",
            "Student": "student_page"}.get(role, "login")


def active_teachers_for_student(sid):
    out = []
    for c in connections:
        if c["student_id"] == sid and c["status"] == "active":
            t = find_user_by_id(c["teacher_id"])
            if t:
                out.append(t)
    return out


def active_students_for_teacher(tid):
    out = []
    for c in connections:
        if c["teacher_id"] == tid and c["status"] == "active":
            s = find_user_by_id(c["student_id"])
            if s:
                out.append(s)
    return out


def classmates_of(student):
    tids = [c["teacher_id"] for c in connections
            if c["student_id"] == student.id and c["status"] == "active"]
    out = []
    seen = set()
    for c in connections:
        if c["teacher_id"] in tids and c["status"] == "active":
            if c["student_id"] == student.id:
                continue
            if c["student_id"] in seen:
                continue
            seen.add(c["student_id"])
            s = find_user_by_id(c["student_id"])
            if s:
                out.append(s)
    return out


def can_view_user(viewer, target):
    if not viewer or not target:
        return False
    if viewer.id == target.id:
        return True
    if viewer.role == "SuperAdmin":
        return True
    for c in connections:
        if c["status"] != "active":
            continue
        if (c["student_id"] == viewer.id and c["teacher_id"] == target.id) or \
           (c["teacher_id"] == viewer.id and c["student_id"] == target.id):
            return True
    if viewer.role == "Student" and target.role == "Student":
        vts = {c["teacher_id"] for c in connections
               if c["student_id"] == viewer.id and c["status"] == "active"}
        tts = {c["teacher_id"] for c in connections
               if c["student_id"] == target.id and c["status"] == "active"}
        if vts & tts:
            return True
    return False


def notify(user_id, title, message, link=None, kind="info"):
    notifications.append({
        "id": uuid.uuid4().hex[:8],
        "user_id": user_id,
        "title": title,
        "message": message,
        "link": link or "",
        "read": False,
        "created_at": now_str(),
        "kind": kind,
    })


def unread_count(uid):
    return sum(1 for n in notifications if n["user_id"] == uid and not n["read"])


def search_users(query, viewer, limit=20):
    if not query:
        return []
    q = query.lower()
    out = []
    for u in users:
        if q not in u.username.lower() and q not in (u.full_name or "").lower():
            continue
        if viewer.role == "SuperAdmin":
            out.append(u)
        elif can_view_user(viewer, u):
            out.append(u)
        if len(out) >= limit:
            break
    return out

def get_int(name, default=0):
    val = request.form.get(name, "")
    if val == "" or val is None:
        return default
    try:
        return int(val)
    except:
        return default

def cleanup_empty_drafts(teacher_id):
    """Delete studies na draft pa at walang laman (empty pages)."""
    to_remove = []
    for s in studies:
        if s.get("teacher_id") != teacher_id:
            continue
        if s.get("status") != "draft":
            continue
        if s.get("published_at"):
            continue
        has_content = any(
            (p.get("question", "") or "").strip()
            for p in s.get("pages", [])
        )
        has_slides = bool(s.get("slides"))
        if not has_content and not has_slides:
            to_remove.append(s)
    for s in to_remove:
        studies.remove(s)
    return len(to_remove)

def cleanup_expired_sessions(study):
    """Alisin ang sessions na expired (>30s walang ping)."""
    # ✅ Skip kung may attempts na — hindi na kailangan
    if study.get("has_attempts"):
        study["active_sessions"] = {}
        return 0

    now = now_dt()
    sessions = study.get("active_sessions") or {}
    expired = []
    for sid, info in sessions.items():
        try:
            last = datetime.strptime(info["last_ping"], "%Y-%m-%d %H:%M:%S")
            if (now - last).total_seconds() > 30:
                expired.append(sid)
        except (ValueError, KeyError, TypeError):
            expired.append(sid)
    for sid in expired:
        del sessions[sid]
    study["active_sessions"] = sessions
    return len(sessions)


def get_active_session_count(study):
    """Bilang ng active students ngayon."""
    return cleanup_expired_sessions(study)


def is_study_locked(study):
    """
    True kung:
      - May submitted attempts na (permanent), OR
      - May active student session (temporary heartbeat)
    """
    if study.get("has_attempts"):
        return True
    if get_active_session_count(study) > 0:
        return True
    return False

def cleanup_stale_editing(teacher_id):
    """
    Auto-restore ng 'editing' studies:
    - Kung teacher nag-click ng Edit pero hindi nag-proceed (modal lang)
      → restore after 2 minutes
    - Kung teacher nag-proceed sa activity.html
      → restore after 15 minutes of inactivity
    """
    restored = 0
    now = now_dt()
    for s in studies:
        if s.get("teacher_id") != teacher_id:
            continue
        if s.get("status") != "editing":
            continue

        last_activity = s.get("edit_started_at") or s.get("updated_at")
        if not last_activity:
            continue

        try:
            try:
                dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M")

            elapsed = (now - dt).total_seconds()

            # ✅ Two-tier timeout
            entered = s.get("entered_activity", False)
            threshold = 120 if entered else 30   # 15 min vs 2 min

            if elapsed > threshold:
                s["status"] = "published"
                s["visible_from"] = (
                    now_dt() + timedelta(seconds=10)
                ).strftime("%Y-%m-%d %H:%M:%S")
                s["updated_at"] = now_str()
                s.pop("edit_started_at", None)
                s.pop("entered_activity", None)
                restored += 1
        except (ValueError, TypeError):
            continue
    return restored


# =====================================================================
# OOP
# =====================================================================
class User:
    def __init__(self, username, password=None, role="User",
                 full_name=None, status="active", password_hash=None):
        # ─── 12-char cryptographically-random ID ───
        self.id = generate_user_id()
        self.username = username
        if password_hash:
            self.__password_hash = password_hash
        else:
            self.__password_hash = hash_password(password)
        self.role = role
        self.full_name = full_name or username
        self.status = status
        self.created_at = now_str()
        self.delete_requested_at = None
        self.delete_grace_until = None
        self.delete_reason = ""
        # ✅ Password reset fields
        self.reset_pending = False
        self.temp_password = None
        self.old_password_hash = None
        self.reset_by = None
        self.reset_at = None

    def check_password(self, p):
        # ─── Constant-time verification via PBKDF2 ───
        return verify_password(p, self.__password_hash)

    def set_password(self, p):
        # ─── Re-hash with fresh salt ───
        self.__password_hash = hash_password(p)

    def reset_with_temp(self):
        """Admin resets: generate temp, backup old hash. Returns temp."""
        self.old_password_hash = self.__password_hash
        self.temp_password = generate_temp_password()
        self.__password_hash = hash_password(self.temp_password)
        self.reset_pending = True
        self.reset_at = now_str()
        return self.temp_password

    def check_old_password(self, p):
        """Verify password against the OLD (pre-reset) hash."""
        if not self.old_password_hash:
            return False
        return verify_password(p, self.old_password_hash)

    def finalize_password_change(self):
        """Clear all reset flags after user successfully changes password."""
        self.reset_pending = False
        self.temp_password = None
        self.old_password_hash = None
        self.reset_by = None
        self.reset_at = None

    def is_active(self):
        return self.status == "active"

    def is_deleted(self):
        return self.status == "deleted"

    def dash(self):
        return "login"

    def to_dict(self, viewer=None, include_id=False):
        d = {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "full_name": self.full_name,
            "status": self.status,
            "created_at": self.created_at,
        }
        # Only Teachers and Students have shareable public IDs.
        # Super Admin does not.
        if self.role in ("Teacher", "Student"):
            if (viewer and viewer.id == self.id) or include_id:
                d["public_id"] = self.id
        return d


class SuperAdmin(User):
    def __init__(self, username, password=None, full_name="Super Admin", password_hash=None):
        super().__init__(username, password, "SuperAdmin", full_name,
                         "active", password_hash)

    def dash(self):
        return "super_admin.html"


class Teacher(User):
    def __init__(self, username, password=None, full_name=None,
                 status="active", password_hash=None):
        super().__init__(username, password, "Teacher",
                         full_name or username, status, password_hash)

    def dash(self):
        return "teacher.html"


class Student(User):
    def __init__(self, username, password=None, full_name=None,
                 status="active", password_hash=None):
        super().__init__(username, password, "Student",
                         full_name or username, status, password_hash)

    def dash(self):
        return "student.html"


# =====================================================================
# DECORATORS
# =====================================================================
def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            is_api = request.path.startswith("/api/")

            if not u:
                if is_api:
                    return jsonify({"ok": False, "error": "Not logged in."}), 401
                flash("Please log in first.", "error")
                return redirect(url_for("login"))

            if u.role not in roles:
                if is_api:
                    return jsonify({"ok": False, "error": "Unauthorized role."}), 403
                flash("Unauthorized access.", "error")
                return redirect(url_for("dashboard"))

            if u.status == "deleted":
                session.clear()
                if is_api:
                    return jsonify({"ok": False, "error": "Account deleted."}), 403
                flash("This account has been deleted.", "error")
                return redirect(url_for("login"))

            return fn(*a, **kw)
        return wrapper
    return decorator


# =====================================================================
# CONTEXT PROCESSOR
# =====================================================================
@app.context_processor
def inject_globals():
    u = current_user()
    if session.get("user_id") and not u:
        session.clear()
        u = None
    return {
        "current_user_obj": u,
        "current_role": u.role if u else None,
        "current_username": u.username if u else None,
        "unread_notifications": unread_count(u.id) if u else 0,
    }


# =====================================================================
# SEED
# =====================================================================
def seed_defaults():
    if not any(u.role == "SuperAdmin" for u in users):
        u = os.getenv("SUPERADMIN_USER")
        p = os.getenv("SUPERADMIN_PASS")
        hashed = hash_password(p)
        users.append(SuperAdmin(username=u,full_name="System Owner",password_hash=hashed))


seed_defaults()


# =====================================================================
# AUTH ROUTES
# =====================================================================
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Public login — auto-detects role. Teachers & Students only."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password required.", "error")
            return redirect(url_for("login"))

        user = find_user_by_username(username)

        # ─── Special: password reset pending ───
        if user and user.reset_pending:
            # Case A: entered OLD password → SHOW temp on login page
            if user.check_old_password(password):
                # ✅ Render login page WITH temp visible
                return render_template(
                    "login.html",
                    show_temp=True,
                    temp_password=user.temp_password,
                    temp_username=user.username,
                    temp_full_name=user.full_name,
                )

            # Case B: entered TEMP password → login OK (force change)
            if password == user.temp_password:
                session["user_id"] = user.id
                session["role"] = user.role
                session["force_password_change"] = True
                flash(
                    "🔓 Logged in with temporary password. "
                    "Please change it in Account Settings.",
                    "warning"
                )
                return redirect(url_for("dashboard"))

            # Case C: neither → normal error
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        # ─── Normal login ───
        if not user or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        if user.role == "SuperAdmin":
            flash("This account must use the system console.", "error")
            return redirect(url_for("login"))

        if user.role not in ("Teacher", "Student"):
            flash("Invalid account role.", "error")
            return redirect(url_for("login"))

        if user.status == "deleted":
            flash("This account has been deleted.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["role"] = user.role
        flash(f"Welcome back, {user.full_name}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/system-console", methods=["GET", "POST"])
def super_admin_login():
    """Secret URL for Super Admin only."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password required.", "error")
            return redirect(url_for("super_admin_login"))

        user = find_user_by_username(username)
        if not user or not user.check_password(password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("super_admin_login"))

        if user.role != "SuperAdmin":
            flash("Access denied.", "error")
            return redirect(url_for("super_admin_login"))

        session["user_id"] = user.id
        session["role"] = user.role
        flash(f"Welcome, {user.full_name}.", "success")
        return redirect(url_for("super_admin_page"))

    return render_template("super_admin_login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        # ─── Restore preserved form values kung may previous error ───
        form_data = session.pop("signup_form", {})
        return render_template("signup.html", form_data=form_data)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    full_name = request.form.get("full_name", "").strip()
    confirm = request.form.get("password_confirm", "")

    # ─── Helper: preserve form values on validation errors ───
    def _signup_error(msg):
        flash(msg, "error")
        session["signup_form"] = {
            "username": username,
            "full_name": full_name,
            "role": role,
        }
        return redirect(url_for("signup"))

    if not username or not password or not role:
        return _signup_error("All fields required.")
    if role not in ("Teacher", "Student"):
        return _signup_error("Invalid role.")
    if find_user_by_username(username):
        return _signup_error("Username taken. Try another.")
    if len(password) < 8:
        return _signup_error("Password must be at least 8 characters.")
    if not confirm:
        return _signup_error("Please confirm your password.")
    if password != confirm:
        return _signup_error("Passwords do not match.")

    if role == "Teacher":
        new_user = Teacher(username, password, full_name)
    else:
        new_user = Student(username, password, full_name)

    users.append(new_user)
    session.pop("signup_form", None)

    # Welcome notification
    notify(new_user.id, "🎉 Welcome!",
           f"Your account ID is {new_user.id}. "
           f"Share this ID with students/teachers to connect.",
           link=f"/{new_user.role.lower()}#account",
           kind="info")

    # ─── AUTO-LOGIN: set session immediately ───
    session["user_id"] = new_user.id
    session["role"] = new_user.role

    flash(f"Welcome, {new_user.full_name}! Your ID is {new_user.id}.",
          "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    # Only block 'deleted' accounts — allow pending_delete & appealed
    # so users can access their dashboard to submit/see their appeal.
    if u.status == "deleted":
        session.clear()
        flash("This account has been deleted.", "error")
        return redirect(url_for("login"))
    t = u.dash()
    if t == "super_admin.html":
        return redirect(url_for("super_admin_page"))
    if t == "teacher.html":
        return redirect(url_for("teacher_page"))
    if t == "student.html":
        return redirect(url_for("student_page"))
    return redirect(url_for("login"))

@app.before_request
def enforce_password_change():
    """Force users with temp password to change it."""
    # ─── Exempt: auth pages, static files, at LAHAT ng API endpoints ───
    exempt_prefixes = (
        "/login", "/logout", "/signup",
        "/api/",                      # ✅ lahat ng API — JSON dapat, hindi redirect
        "/static", "/system-console",
    )
    if any(request.path.startswith(p) for p in exempt_prefixes):
        return

    if session.get("force_password_change"):
        # Allow: dashboards, profile, at account section lang
        allowed = ("/teacher", "/student", "/super-admin", "/dashboard")
        if request.path not in allowed and not request.path.startswith("/profile"):
            return redirect(url_for("dashboard"))
        
# =====================================================================
# DASHBOARDS
# =====================================================================
@app.route("/super-admin")
@role_required("SuperAdmin")
def super_admin_page():
    u = current_user()
    pending_deletes = [x for x in users if x.status in ("pending_delete", "appealed")]

    def user_with_reset_info(x):
        d = x.to_dict(viewer=u)
        d["reset_pending"] = x.reset_pending
        return d

    return render_template(
        "super_admin.html",
        user=u,
        all_users=[user_with_reset_info(x) for x in users
                   if x.status != "deleted"],
        teachers=[user_with_reset_info(x) for x in users
                  if x.role == "Teacher" and x.status != "deleted"],
        students=[user_with_reset_info(x) for x in users
                  if x.role == "Student" and x.status != "deleted"],
        studies=studies,
        results=quiz_results,
        attendance=attendance,
        pending_deletes=[user_with_reset_info(x) for x in pending_deletes],
        total_notifications=len(notifications),
    )

@app.route("/teacher")
@role_required("Teacher")
def teacher_page():
    u = current_user()
    cleanup_empty_drafts(u.id)
    cleanup_stale_editing(u.id)          # ✅ BAGO — restore stale editing

    my_students = active_students_for_teacher(u.id)
    pending_in = [c for c in connections
                  if c["teacher_id"] == u.id and c["status"] == "pending"
                  and c["requested_by"] == "student"]
    pending_out = [c for c in connections
                   if c["teacher_id"] == u.id and c["status"] == "pending"
                   and c["requested_by"] == "teacher"]

    my_studies = [
        s for s in studies
        if s["teacher_id"] == u.id
        and s.get("status") in ("published", "editing")
    ]
    my_studies.sort(key=lambda s: s.get("updated_at", ""), reverse=True)

    # ✅ Compute live lock status for each study
    for s in my_studies:
        s["is_locked"] = is_study_locked(s)
        s["active_count"] = get_active_session_count(s)

    visible_ids = {s["id"] for s in my_studies}
    my_results = [r for r in quiz_results if r["study_id"] in visible_ids]
    my_results.sort(key=lambda r: r["timestamp"], reverse=True)
    my_attendance = [a for a in attendance if a["teacher_id"] == u.id]
    my_attendance.sort(key=lambda a: a["timestamp"], reverse=True)

    pending_in_details = []
    for c in pending_in:
        s = find_user_by_id(c["student_id"])
        if s:
            pending_in_details.append({"conn": c, "student": s.to_dict(viewer=u)})
    pending_out_details = []
    for c in pending_out:
        s = find_user_by_id(c["student_id"])
        if s:
            pending_out_details.append({"conn": c, "student": s.to_dict(viewer=u)})

    return render_template(
        "teacher.html",
        user=u,
        students=[s.to_dict(viewer=u) for s in my_students],
        pending_in=pending_in_details,
        pending_out=pending_out_details,
        studies=my_studies,
        results=my_results,
        attendance=my_attendance,
        today=today_str(),
        my_id=u.id,
        show_temp_reset=u.reset_pending,
        temp_password=u.temp_password if u.reset_pending else None,
    )


@app.route("/student")
@role_required("Student")
def student_page():
    u = current_user()
    my_teachers = active_teachers_for_student(u.id)
    classmates = classmates_of(u)
    pending_in = [c for c in connections
                  if c["student_id"] == u.id and c["status"] == "pending"
                  and c["requested_by"] == "teacher"]
    pending_out = [c for c in connections
                   if c["student_id"] == u.id and c["status"] == "pending"
                   and c["requested_by"] == "student"]

    pending_in_details = []
    for c in pending_in:
        t = find_user_by_id(c["teacher_id"])
        if t:
            pending_in_details.append({"conn": c, "teacher": t.to_dict(viewer=u)})
    pending_out_details = []
    for c in pending_out:
        t = find_user_by_id(c["teacher_id"])
        if t:
            pending_out_details.append({"conn": c, "teacher": t.to_dict(viewer=u)})

    teacher_ids = {t.id for t in my_teachers}

    # ✅ Only published + (visible_from is None OR visible_from <= now)
    now = now_dt()
    def _is_visible(s):
        if s["teacher_id"] not in teacher_ids: return False
        if s.get("status") != "published": return False
        vf = s.get("visible_from")
        if vf:
            try:
                if datetime.strptime(vf, "%Y-%m-%d %H:%M:%S") > now:
                    return False
            except (ValueError, TypeError):
                pass
        return True

    visible_studies = [s for s in studies if _is_visible(s)]

    attempted_ids = {r["study_id"] for r in quiz_results if r["student_id"] == u.id}

    safe_studies = []
    for s in visible_studies:
        safe_pages = [
            {"question": p.get("question", ""), "description": p.get("description", "")}
            for p in s.get("pages", [])
        ]
        safe_slides = []
        for sl in (s.get("slides") or []):
            if isinstance(sl, str):
                safe_slides.append({"text": sl})
            elif isinstance(sl, dict):
                safe_slides.append({"text": sl.get("text", "")})

        safe_studies.append({
            "id": s["id"],
            "title": s["title"],
            "type": s.get("type", "identification"),
            "direction": s.get("direction", ""),
            "study_timer": int(s.get("study_timer") or 0),
            "question_timer": int(s.get("question_timer") or 30),
            "max_back": int(s.get("max_back") or 0),
            "score": int(s.get("score") or 0),
            "penalty": int(s.get("penalty") or 0),
            "teacher_name": s.get("teacher_name", ""),
            "pages": safe_pages,
            "has_ppt": bool(safe_slides),
            "slides": safe_slides,
            "already_done": s["id"] in attempted_ids,
        })

    my_results = [r for r in quiz_results if r["student_id"] == u.id]
    my_results.sort(key=lambda r: r["timestamp"], reverse=True)
    my_attendance = [a for a in attendance if a["student_id"] == u.id]
    my_attendance.sort(key=lambda a: a["date"], reverse=True)

    lb = build_leaderboard()
    my_rank = next((r["rank"] for r in lb if r["id"] == u.id), None)
    my_points = sum(r["score"] for r in my_results)

    return render_template(
        "student.html",
        user=u,
        teachers=[t.to_dict(viewer=u) for t in my_teachers],
        classmates=[c.to_dict(viewer=u) for c in classmates],
        pending_in=pending_in_details,
        pending_out=pending_out_details,
        studies=safe_studies,
        results=my_results,
        attendance=my_attendance,
        leaderboard=lb,
        my_rank=my_rank,
        my_points=my_points,
        my_id=u.id,
        show_temp_reset=u.reset_pending,
        temp_password=u.temp_password if u.reset_pending else None,
    )




# =====================================================================
# CONNECTIONS
# =====================================================================
@app.route("/api/connections/request", methods=["POST"])
@role_required("Teacher", "Student")
def request_connection():
    actor = current_user()
    target_id = request.form.get("target_id", "").strip().upper()
    if not target_id:
        flash("Please enter an ID.", "error")
        return redirect(url_for(role_home(actor.role)))

    if target_id == actor.id:
        flash("You cannot connect to yourself.", "error")
        return redirect(url_for(role_home(actor.role)))

    target = find_user_by_id(target_id)
    if not target:
        flash(f"No user found with ID {target_id}.", "error")
        return redirect(url_for(role_home(actor.role)))

    # Only Teacher <-> Student connections are valid
    if {actor.role, target.role} != {"Teacher", "Student"}:
        flash("Invalid connection request.", "error")
        return redirect(url_for(role_home(actor.role)))

    if actor.role == "Student":
        student, teacher = actor, target
    else:
        student, teacher = target, actor

    for c in connections:
        if c["student_id"] == student.id and c["teacher_id"] == teacher.id:
            if c["status"] == "active":
                flash("You are already connected.", "error")
            else:
                flash("A pending request already exists.", "error")
            return redirect(url_for(role_home(actor.role)))

    conn = {
        "id": uuid.uuid4().hex[:8],
        "student_id": student.id,
        "teacher_id": teacher.id,
        "status": "pending",
        "requested_by": actor.role.lower(),
        "created_at": now_str(),
    }
    connections.append(conn)

    other = target
    notify(other.id, "New Connection Request",
           f"{actor.full_name} (@{actor.username}) wants to connect with you.",
           link=f"/{other.role.lower()}#connect", kind="connection_request")

    flash(f"Request sent to {target.full_name}!", "success")
    return redirect(url_for(role_home(actor.role)))


@app.route("/api/connections/<cid>/approve", methods=["POST"])
@role_required("Teacher", "Student")
def approve_connection(cid):
    actor = current_user()
    conn = next((c for c in connections if c["id"] == cid), None)
    if not conn:
        flash("Request not found.", "error")
        return redirect(url_for(role_home(actor.role)))
    if conn["requested_by"] == actor.role.lower():
        flash("You cannot approve your own request.", "error")
        return redirect(url_for(role_home(actor.role)))
    if actor.id not in (conn["student_id"], conn["teacher_id"]):
        flash("Not your request.", "error")
        return redirect(url_for(role_home(actor.role)))

    conn["status"] = "active"

    other_id = conn["teacher_id"] if actor.id == conn["student_id"] else conn["student_id"]
    other = find_user_by_id(other_id)
    if other:
        # Student → #teachers section
        # Teacher → #students section
        target_section = "teachers" if other.role == "Student" else "students"
        notify(other_id, "Connection Approved",
               f"{actor.full_name} accepted your connection request.",
               link=f"/{other.role.lower()}#{target_section}",
               kind="connection_approved")
    flash("Connection approved!", "success")
    return redirect(url_for(role_home(actor.role)))


@app.route("/api/connections/<cid>/reject", methods=["POST"])
@role_required("Teacher", "Student")
def reject_connection(cid):
    actor = current_user()
    conn = next((c for c in connections if c["id"] == cid), None)
    if not conn:
        flash("Request not found.", "error")
        return redirect(url_for(role_home(actor.role)))
    if actor.id not in (conn["student_id"], conn["teacher_id"]):
        flash("Not your request.", "error")
        return redirect(url_for(role_home(actor.role)))

    other_id = conn["teacher_id"] if actor.id == conn["student_id"] else conn["student_id"]
    connections.remove(conn)
    other = find_user_by_id(other_id)
    if other:
        notify(other_id, "Connection Rejected",
               f"{actor.full_name} declined your connection request.",
               link=f"/{other.role.lower()}#connect",
               kind="connection_rejected")
    flash("Request rejected.", "success")
    return redirect(url_for(role_home(actor.role)))


# =====================================================================
# PROFILE
# =====================================================================
@app.route("/profile/<username>")
def profile(username):
    viewer = current_user()
    if not viewer:
        return redirect(url_for("login"))

    target = find_user_by_username(username)
    if not target or target.status == "deleted":
        flash("User not found.", "error")
        return redirect(url_for("dashboard"))

    if not can_view_user(viewer, target):
        flash("You cannot view this profile.", "error")
        return redirect(url_for("dashboard"))

    ctx = {
        "user": viewer,
        "target": target.to_dict(viewer=viewer),
        "target_obj": target,
        "target_role": target.role,
        "is_owner": viewer.id == target.id,
        "results": [], "attendance": [], "leaderboard": [],
        "medals": {"Gold": 0, "Silver": 0, "Bronze": 0},
        "total_points": 0, "rank": None,
        "rating": {"average": 0.0, "count": 0},
        "studies": [],
    }

    if target.role == "Student":
        res = [r for r in quiz_results if r["student_id"] == target.id]
        res.sort(key=lambda r: r["timestamp"], reverse=True)
        ctx["results"] = res
        ctx["total_points"] = sum(r["score"] for r in res)
        for r in res:
            if r.get("medal"):
                ctx["medals"][r["medal"]] += 1
        ctx["attendance"] = sorted(
            [a for a in attendance if a["student_id"] == target.id],
            key=lambda a: a["date"], reverse=True)
        lb = build_leaderboard()
        ctx["leaderboard"] = lb[:10]
        ctx["rank"] = next((r["rank"] for r in lb if r["id"] == target.id), None)

    elif target.role == "Teacher":
        ctx["studies"] = [s for s in studies if s["teacher_id"] == target.id]
    return render_template("profile.html", **ctx)


# =====================================================================
# NOTIFICATIONS
# =====================================================================
@app.route("/api/notifications")
def api_notifications():
    u = current_user()
    if not u:
        return jsonify([])
    mine = [n for n in notifications if n["user_id"] == u.id]
    mine.sort(key=lambda n: n["created_at"], reverse=True)
    return jsonify(mine[:30])


@app.route("/api/notifications/<nid>/read", methods=["POST"])
def mark_read(nid):
    u = current_user()
    if not u:
        return jsonify({"ok": False}), 401
    n = next((x for x in notifications if x["id"] == nid and x["user_id"] == u.id), None)
    if n:
        n["read"] = True
    return jsonify({"ok": True})


@app.route("/api/notifications/read-all", methods=["POST"])
def mark_all_read():
    u = current_user()
    if not u:
        return jsonify({"ok": False}), 401
    for n in notifications:
        if n["user_id"] == u.id:
            n["read"] = True
    return jsonify({"ok": True})


# =====================================================================
# SEARCH
# =====================================================================
@app.route("/api/search")
def api_search():
    u = current_user()
    if not u:
        return jsonify([])
    q = request.args.get("q", "").strip()
    found = search_users(q, u)
    return jsonify([x.to_dict(viewer=u) for x in found])


# =====================================================================
# SOFT DELETE / APPEAL
# =====================================================================
@app.route("/api/admin/delete/<uid>/flag", methods=["POST"])
@role_required("SuperAdmin")
def admin_flag_user(uid):
    """Super Admin flags a user for deletion with reason + timer."""
    admin = current_user()
    target = find_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("super_admin_page"))
    if target.role == "SuperAdmin":
        flash("Cannot delete Super Admin.", "error")
        return redirect(url_for("super_admin_page"))

    reason = request.form.get("reason", "").strip()
    try:
        duration = int(request.form.get("duration", "7"))
    except ValueError:
        duration = 7
    unit = request.form.get("unit", "days").strip()

    if not reason:
        flash("Reason is required.", "error")
        return redirect(url_for("super_admin_page"))
    if duration < 1:
        flash("Duration must be at least 1.", "error")
        return redirect(url_for("super_admin_page"))

    # Compute grace period
    if unit == "hours":
        grace = timedelta(hours=duration)
        unit_label = f"{duration} hour(s)"
    elif unit == "months":
        grace = timedelta(days=30 * duration)
        unit_label = f"{duration} month(s)"
    else:  # days (default)
        grace = timedelta(days=duration)
        unit_label = f"{duration} day(s)"

    target.status = "pending_delete"
    target.delete_requested_at = now_str()
    target.delete_grace_until = (now_dt() + grace).strftime("%Y-%m-%d %H:%M")
    target.delete_reason = reason

    # Notify the target user
    notify(target.id, "⚠️ Account Deletion Notice",
           f"Your account has been flagged for deletion by an admin. "
           f"Reason: {reason}. Deletion scheduled in {unit_label} "
           f"(on {target.delete_grace_until}). You may appeal.",
           link=f"/{target.role.lower()}#account",
           kind="delete_notice")

    # Notify admin (log)
    notify(admin.id, "Deletion Scheduled",
           f"You flagged {target.full_name} (@{target.username}) for deletion in {unit_label}.",
           link="/super-admin#deletes",
           kind="info")

    flash(f"Deletion scheduled for {target.full_name} in {unit_label}.", "success")
    return redirect(url_for("super_admin_page"))


@app.route("/api/account/appeal", methods=["POST"])
@role_required("Teacher", "Student")
def appeal_delete():
    u = current_user()
    message = request.form.get("message", "").strip()
    if u.status != "pending_delete":
        flash("No deletion to appeal.", "error")
        return redirect(url_for("dashboard"))
    u.status = "appealed"

    for x in users:
        if x.role == "SuperAdmin":
            notify(x.id, "📩 Appeal Received",
                   f"{u.full_name} (@{u.username}) appealed their deletion. "
                   f"Message: {message[:120]}",
                   link="/super-admin#deletes",
                   kind="appeal")

    notify(u.id, "Appeal Submitted",
           "Your appeal has been sent to the Super Admin for review.",
           link=f"/{u.role.lower()}#account", kind="info")

    flash("Appeal submitted. Super Admin will review.", "success")
    return redirect(url_for("dashboard"))


@app.route("/api/account/appeal/cancel", methods=["POST"])
@role_required("Teacher", "Student")
def cancel_delete():
    u = current_user()
    if u.status != "pending_delete":
        flash("Nothing to cancel.", "error")
        return redirect(url_for("dashboard"))
    u.status = "active"
    u.delete_requested_at = None
    u.delete_grace_until = None
    u.delete_reason = ""
    flash("Account deletion cancelled. Welcome back!", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/account/password", methods=["POST"])
@role_required("Teacher", "Student")
def change_password():
    u = current_user()
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")

    # Detect AJAX request (from the modal)
    wants_json = (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                  or request.form.get("_ajax") == "1")

    def _err(msg):
        if wants_json:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for(role_home(u.role)))

    if not u.check_password(current):
        return _err("Current password is incorrect.")
    if len(new) < 8:
        return _err("New password must be at least 8 characters.")
    if new != confirm:
        return _err("New passwords do not match.")
    if new == current:
        return _err("New password must be different from current.")

    u.set_password(new)
    u.finalize_password_change()        # ✅ NEW — clear reset flags
    session.pop("force_password_change", None)   # ✅ Clear force flag

    notify(u.id, "Password Changed",
           "Your password was updated successfully.",
           link=f"/{u.role.lower()}#account", kind="info")

    if wants_json:
        return jsonify({"ok": True, "message": "Password updated successfully!"})

    flash("Password updated successfully!", "success")
    return redirect(url_for(role_home(u.role)))

@app.route("/api/admin/delete/<uid>/approve", methods=["POST"])
@role_required("SuperAdmin")
def admin_approve_delete(uid):
    target = find_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("super_admin_page"))
    target.status = "deleted"
    target.username = f"deleted_{target.id}"
    notify(target.id, "Account Deleted", "Your account has been deleted.", kind="info")
    flash(f"Deleted {target.full_name}.", "success")
    return redirect(url_for("super_admin_page"))


@app.route("/api/admin/delete/<uid>/reject", methods=["POST"])
@role_required("SuperAdmin")
def admin_reject_delete(uid):
    target = find_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("super_admin_page"))
    target.status = "active"
    target.delete_requested_at = None
    target.delete_grace_until = None
    target.delete_reason = ""
    notify(target.id, "Deletion Cancelled",
           "Super Admin rejected the deletion. Your account is active.",
           link=f"/{target.role.lower()}#account", kind="info")
    flash(f"Restored {target.full_name}.", "success")
    return redirect(url_for("super_admin_page"))


# =====================================================================
# SUPER ADMIN — USER DELETE
# =====================================================================
@app.route("/api/users/<uid>/delete", methods=["POST"])
@role_required("SuperAdmin")
def admin_hard_delete(uid):
    target = find_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("super_admin_page"))
    if target.role == "SuperAdmin":
        flash("Cannot delete Super Admin.", "error")
        return redirect(url_for("super_admin_page"))
    users.remove(target)
    studies[:] = [s for s in studies if s.get("teacher_id") != uid]
    quiz_results[:] = [r for r in quiz_results if r["student_id"] != uid]
    attendance[:] = [a for a in attendance if a["student_id"] != uid]
    connections[:] = [c for c in connections
                      if c["student_id"] != uid and c["teacher_id"] != uid]
    flash(f"User '{target.username}' permanently deleted.", "success")
    return redirect(url_for("super_admin_page"))


@app.route("/api/admin/users/<uid>/reset-password", methods=["POST"])
@role_required("SuperAdmin")
def admin_reset_user_password(uid):
    """Generate temp password for user. Shown to admin only."""
    admin = current_user()
    target = find_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("super_admin_page"))
    if target.role == "SuperAdmin":
        flash("Cannot reset SuperAdmin password this way.", "error")
        return redirect(url_for("super_admin_page"))
    if target.status == "deleted":
        flash("Cannot reset deleted account.", "error")
        return redirect(url_for("super_admin_page"))

    temp = target.reset_with_temp()
    target.reset_by = admin.id

    # Notify admin — this is where admin sees the temp password
    notify(admin.id, "🔑 Password Reset Successful",
           f"Temporary password for @{target.username} "
           f"({target.full_name}): {temp} — "
           f"User must log in with their OLD password first to view this temp.",
           link="/super-admin#users",
           kind="reset")

    # Notify user — they don't see temp here, only hint
    user_link = f"/{target.role.lower()}#account"
    notify(target.id, "🔑 Password Reset by Admin",
           "Your password was reset. To view your new temporary password, "
           "log in using your OLD password and username.",
           link=user_link,
           kind="reset")

    flash(f"✅ Password reset for {target.full_name}. Temp: {temp}", "success")
    return redirect(url_for("super_admin_page"))

@app.route("/api/admin/users/<uid>/reset-password-json", methods=["POST"])
@role_required("SuperAdmin")
def admin_reset_password_json(uid):
    """JSON version — walang temp sa response. Nasa user side lang."""
    admin = current_user()
    target = find_user_by_id(uid)
    if not target:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if target.role == "SuperAdmin":
        return jsonify({"ok": False, "error": "Cannot reset SuperAdmin."}), 400
    if target.status == "deleted":
        return jsonify({"ok": False, "error": "Account is deleted."}), 400

    target.reset_with_temp()
    target.reset_by = admin.id

    # Notify admin — WALANG temp, reminder lang
    notify(admin.id, "🔑 Password Reset Done",
           f"Password reset for @{target.username}. "
           f"User must log in with their OLD password to view the temp password.",
           link="/super-admin#teachers",
           kind="reset")

    # Notify user — hint lang, walang temp
    # ✅ Redirect sa Account section ng tamang dashboard
    user_link = f"/{target.role.lower()}#account"
    notify(target.id, "🔑 Password Reset by Admin",
           "Your password was reset. Log in with your OLD password "
           "to view your temporary password on the login page.",
           link=user_link,
           kind="reset")

    # ✅ WALANG temp_password sa response
    return jsonify({
        "ok": True,
        "username": target.username,
        "full_name": target.full_name
    })

# =====================================================================
# STUDIES CRUD (Teacher)
# =====================================================================
@app.route("/api/studies/create_draft", methods=["POST"])
@role_required("Teacher")
def create_draft():
    actor = current_user()
    title = request.form.get("title", "").strip() or "Untitled Study"
    study_type = request.form.get("type", "identification").strip()
    mode = request.form.get("mode", "direct_quiz").strip()
    direction = request.form.get("direction", "").strip()

    if study_type not in ("identification", "multiple_choice", "true_false", "essay", "file_upload"):
        study_type = "identification"
    if mode not in ("direct_quiz", "study_and_quiz"):
        mode = "direct_quiz"

    score = get_int("score", 1)
    penalty = get_int("penalty", 0)
    study_timer = get_int("study_timer", 0) if mode == "study_and_quiz" else 0
    question_timer = get_int("question_timer", 10)
    max_back = get_int("max_back", 0)
    total_pages = max(1, get_int("total_pages", 1))
    mc_options = get_int("mc_options", 4)
    if mc_options not in (3, 4):
        mc_options = 4

    if question_timer <= 0:
        return jsonify({"error": "Question timer must be positive."}), 400

    # Default empty page structure
    def empty_page():
        p = {"question": ""}
        if study_type == "identification":
            p["correct_answer"] = ""
        elif study_type == "multiple_choice":
            p["choices"] = ["" for _ in range(mc_options)]
            p["correct_index"] = 0
        elif study_type == "true_false":
            p["correct_bool"] = True
        elif study_type == "essay":
            p["reference"] = ""
        elif study_type == "file_upload":
            p["instruction"] = ""
        return p

    new_id = uuid.uuid4().hex[:8]
    new_study = {
        "id": new_id,
        "teacher_id": actor.id,
        "teacher_name": actor.username,
        "title": title,
        "type": study_type or "identification",
        "mode": mode,
        "direction": direction,
        "study_timer": max(0, study_timer),
        "question_timer": max(1, question_timer),
        "max_back": max(0, max_back),
        "total_pages": total_pages,
        "mc_options": mc_options if study_type == "multiple_choice" else 0,
        "pages": [empty_page() for _ in range(total_pages)],
        "slides": [],
        "score": max(0, score),
        "penalty": max(0, penalty),
        "allow_retry": False,
        "status": "draft",
        "has_attempts": False,
        "locked": False,                # ✅ ADD
        "locked_at": None,              # ✅ ADD
        "locked_until": None,       # ✅ ADD
        "active_sessions": {},
        "published_at": None,
        "visible_from": None,
        "created_at": now_str(),
        "updated_at": now_str(),
    }
    studies.append(new_study)
    return jsonify({"id": new_id})


@app.route("/api/studies/<stid>/update", methods=["POST"])
@role_required("Teacher")
def update_study(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Not found or not yours.", "error")
        return redirect(url_for("teacher_page"))

    # ✅ FIX: Hindi na required ang title — i-preserve kung wala
    title = request.form.get("title", "").strip() or study.get("title", "Untitled Study")

    study_type = request.form.get("type", study.get("type", "identification")).strip()
    if study_type not in ("identification", "multiple_choice", "true_false", "essay", "file_upload"):
        study_type = study.get("type", "identification")

    mode = request.form.get("mode", study.get("mode", "direct_quiz")).strip()
    if mode not in ("direct_quiz", "study_and_quiz"):
        mode = study.get("mode", "direct_quiz")

    mc_options = get_int("mc_options", study.get("mc_options", 4))
    if mc_options not in (3, 4):
        mc_options = 4

    study.update({
        "title": title,
        "type": study_type,
        "mode": mode,
        "direction": request.form.get("direction", study.get("direction", "")).strip(),
        "study_timer": max(0, get_int("study_timer", study.get("study_timer", 0))),
        "question_timer": max(1, get_int("question_timer", study.get("question_timer", 30))),
        "max_back": max(0, get_int("max_back", study.get("max_back", 0))),
        "score": max(0, get_int("score", study.get("score", 0))),
        "penalty": max(0, get_int("penalty", study.get("penalty", 0))),
        "mc_options": mc_options if study_type == "multiple_choice" else 0,
        "updated_at": now_str(),
    })

    flash("Settings updated. Now edit questions.", "success")
    return redirect(url_for("teacher_page"))



@app.route("/api/studies/<stid>/save_page/<int:page_idx>", methods=["POST"])
@role_required("Teacher")
def save_page(stid, page_idx):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Study not found.", "error")
        return redirect(url_for("teacher_page"))
    
    if is_study_locked(study):
        flash("🔒 Cannot edit — may student na nagsimula.", "error")
        return redirect(url_for("teacher_page"))

    # Update title/direction
    new_title = request.form.get("title", "").strip()
    if new_title:
        study["title"] = new_title
    if "direction" in request.form:
        study["direction"] = request.form.get("direction", "").strip()

    while len(study["pages"]) <= page_idx:
        study["pages"].append({"question": ""})

    page = study["pages"][page_idx]
    page["question"] = request.form.get("question", "").strip()
    stype = study["type"]

    if stype == "identification":
        page["correct_answer"] = request.form.get("correct_answer", "").strip()

    elif stype == "multiple_choice":
        n = study.get("mc_options", 4)
        page["choices"] = [request.form.get(f"choice_{i}", "").strip() for i in range(n)]
        try:
            page["correct_index"] = int(request.form.get("correct_index", 0))
        except ValueError:
            page["correct_index"] = 0

    elif stype == "true_false":
        val = request.form.get("correct_bool", "true")
        page["correct_bool"] = (val == "true")

    elif stype == "essay":
        page["reference"] = request.form.get("reference", "").strip()

    elif stype == "file_upload":
        page["instruction"] = request.form.get("instruction", "").strip()

    study["updated_at"] = now_str()

    if page_idx + 1 < study["total_pages"]:
        return redirect(f"/teacher/activity/{stid}/{page_idx + 1}")

    return redirect(f"/teacher/activity/{stid}/preview")


@app.route("/teacher/activity/<stid>/<int:page_idx>", methods=["GET", "POST"])
@role_required("Teacher")
def activity_builder(stid, page_idx):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Study not found or not yours.", "error")
        return redirect(url_for("teacher_page"))

    # ✅ BLOCK: locked na (student nasa session o may attempts na)
    if is_study_locked(study):
        flash("🔒 Cannot edit — may student na nagsimula ng quiz. "
              "Wait for them to finish or lock to expire.", "error")
        return redirect(url_for("teacher_page"))


    # ✅ AUTO-HIDE: kapag published, i-hide habang nag-e-edit
    if study.get("status") == "published":
        study["status"] = "editing"
        study["updated_at"] = now_str()
        notify(actor.id, "✏️ Study Hidden",
               f"'{study['title']}' is temporarily hidden from students while you edit it.",
               link="/teacher#studies", kind="info")

    # ✅ Refresh edit timestamp — teacher is actively editing
    if study.get("status") == "editing":
        study["edit_started_at"] = now_dt().strftime("%Y-%m-%d %H:%M:%S")
        study["entered_activity"] = True      # ✅ NEW — tuloy tuloy na

    return render_template("activity.html", study=study, page_idx=page_idx)


@app.route("/teacher/activity/<stid>/preview", methods=["GET", "POST"])
@role_required("Teacher")
def activity_preview(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Study not found or not yours.", "error")
        return redirect(url_for("teacher_page"))

    # ✅ BLOCK kung locked
    if is_study_locked(study):
        flash("🔒 Cannot edit — may student na nagsimula ng quiz.", "error")
        return redirect(url_for("teacher_page"))

    # Auto-hide
    if study.get("status") == "published":
        study["status"] = "editing"
        study["updated_at"] = now_str()

    # ✅ Refresh edit timestamp
    if study.get("status") == "editing":
        study["edit_started_at"] = now_dt().strftime("%Y-%m-%d %H:%M:%S")
        study["entered_activity"] = True      # ✅ NEW

    return render_template("activity.html", study=study, is_preview=True)


@app.route("/api/studies/<stid>/publish", methods=["POST"])
@role_required("Teacher")
def publish_study(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Study not found.", "error")
        return redirect(url_for("teacher_page"))

    # ✅ BLOCK kung locked
    if is_study_locked(study):
        flash("🔒 Cannot publish — may student na nagsimula ng quiz.", "error")
        return redirect(url_for("teacher_page"))

    # Validate per type
    stype = study.get("type", "identification")
    for i, p in enumerate(study["pages"]):
        if not p.get("question"):
            flash(f"Cannot publish — page {i+1} has no question.", "error")
            return redirect(f"/teacher/activity/{stid}/preview")
        if stype == "identification" and not p.get("correct_answer"):
            flash(f"Cannot publish — page {i+1} has no answer.", "error")
            return redirect(f"/teacher/activity/{stid}/preview")
        if stype == "multiple_choice":
            if not p.get("choices") or any(not c for c in p["choices"]):
                flash(f"Cannot publish — page {i+1} has empty choices.", "error")
                return redirect(f"/teacher/activity/{stid}/preview")


    # ✅ Publish + ALWAYS 10s delay
    study["status"] = "published"
    study["has_attempts"] = False
    study["published_at"] = now_str() 
    study["visible_from"] = (now_dt() + timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
    study["updated_at"] = now_str()

    for s in active_students_for_teacher(actor.id):
        notify(s.id, "📚 New Study Posted",
               f"{actor.full_name} posted '{study['title']}'. Available in 10 seconds.",
               link="/student#studies", kind="study")

    flash(f"'{study['title']}' published! Students will see it in 10 seconds.", "success")
    return redirect(url_for("teacher_page"))

@app.route("/api/studies/<stid>/ping", methods=["POST"])
@role_required("Student")
def ping_study(stid):
    """Student heartbeat — every 10s habang nasa activity page."""
    actor = current_user()
    study = find_study(stid)
    if not study:
        return jsonify({"ok": False, "error": "Not found"}), 404

    # Hindi na kailangan ping kung permanent lock na
    if study.get("has_attempts"):
        return jsonify({"ok": True, "locked": True})

    if "active_sessions" not in study:
        study["active_sessions"] = {}

    study["active_sessions"][actor.id] = {
        "last_ping": now_dt().strftime("%Y-%m-%d %H:%M:%S"),
        "started_at": study["active_sessions"].get(actor.id, {}).get(
            "started_at", now_str()
        ),
    }
    return jsonify({"ok": True, "active": get_active_session_count(study)})

# ═══════════════════════════════════════════════════════════
# SAVE SLIDES (PPT)
# ═══════════════════════════════════════════════════════════
@app.route("/api/studies/<stid>/save_slides", methods=["POST"])
@role_required("Teacher")
def save_slides(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"ok": False, "error": "Not found"}), 404
    
    if is_study_locked(study):
        return jsonify({"ok": False, "error": "Study is locked — may student na nagsimula."}), 403
    

    data = request.get_json(silent=True) or {}
    slides = data.get("slides", [])

    clean = []
    for s in slides:
        if isinstance(s, str):
            if s.strip():
                clean.append({"text": s.strip()})
        elif isinstance(s, dict) and s.get("text"):
            clean.append({"text": str(s["text"]).strip()})

    study["slides"] = clean
    study["updated_at"] = now_str()
    return jsonify({"ok": True, "count": len(clean)})

@app.route("/api/studies/<stid>/start_edit", methods=["POST"])
@role_required("Teacher")
def start_edit_study(stid):
    """I-hide agad ang study sa student pag-click ng Edit sa modal."""
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"ok": False, "error": "Not found"}), 404

    # ✅ BLOCK kung locked (safety check kahit naka-hide na ang button)
    if is_study_locked(study):
        return jsonify({"ok": False, "error": "Study is locked."}), 403

    if study.get("status") == "published":
        study["status"] = "editing"
        study["edit_started_at"] = now_dt().strftime("%Y-%m-%d %H:%M:%S")
        study["entered_activity"] = False     # ✅ NEW — hindi pa nag-proceed
        study["updated_at"] = now_str()
        for s in active_students_for_teacher(actor.id):
            notify(s.id, "📚 Study Update",
                   f"'{study['title']}' is being updated. Please wait.",
                   link="/student#studies", kind="info")

    return jsonify({"ok": True, "status": study["status"]})

@app.route("/api/studies/<stid>/cancel_edit", methods=["POST"])
@role_required("Teacher")
def cancel_edit_study(stid):
    """I-restore ang study kung nag-cancel si teacher sa modal (hindi nag-proceed)."""
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"ok": False, "error": "Not found"}), 404

    # Restore kung naka-editing pa
    if study.get("status") == "editing":
        # ✅ Huwag i-restore kung may attempts na (permanent lock)
        if study.get("has_attempts"):
            return jsonify({"ok": False, "error": "Has attempts — permanent."}), 400

        study["status"] = "published"
        study["visible_from"] = (
            now_dt() + timedelta(seconds=10)
        ).strftime("%Y-%m-%d %H:%M:%S")
        study["updated_at"] = now_str()
        study.pop("edit_started_at", None)   # ✅ Cleanup
        study.pop("entered_activity", None)   # ✅ NEW

    return jsonify({"ok": True, "status": study["status"]})

# ═══════════════════════════════════════════════════════════
# STUDENT ACTIVITY PAGE
# ═══════════════════════════════════════════════════════════
@app.route("/student/activity/<stid>")
@role_required("Student")
def student_activity(stid):
    actor = current_user()
    study = find_study(stid)
    if not study:
        flash("Study not found.", "error")
        return redirect(url_for("student_page"))

    tids = {t.id for t in active_teachers_for_student(actor.id)}
    if study["teacher_id"] not in tids:
        flash("Not connected to this teacher.", "error")
        return redirect(url_for("student_page"))

    if study.get("status") != "published":
        flash("Study is not yet available.", "error")
        return redirect(url_for("student_page"))

    # Check visible_from (10s delay)
    vf = study.get("visible_from")
    if vf:
        try:
            if datetime.strptime(vf, "%Y-%m-%d %H:%M:%S") > now_dt():
                flash("Study is not yet available. Please wait a few seconds.", "error")
                return redirect(url_for("student_page"))
        except (ValueError, TypeError):
            pass

    already = next((r for r in quiz_results
                    if r["student_id"] == actor.id and r["study_id"] == stid), None)
    if already and not study.get("allow_retry"):
        flash("Already submitted.", "error")
        return redirect(url_for("student_page"))

    # ✅ HEARTBEAT: register session on load
    if not study.get("has_attempts"):
        if "active_sessions" not in study:
            study["active_sessions"] = {}

        was_empty = len(study["active_sessions"]) == 0
        study["active_sessions"][actor.id] = {
            "last_ping": now_dt().strftime("%Y-%m-%d %H:%M:%S"),
            "started_at": study["active_sessions"].get(actor.id, {}).get(
                "started_at", now_str()
            ),
        }
        study["updated_at"] = now_str()

        # Notify teacher sa first active session lang
        if was_empty:
            notify(study["teacher_id"], "🔒 Study In Use",
                   f"May student na nagsimula ng '{study['title']}'.",
                   link="/teacher#studies", kind="info")

    stype = study.get("type", "identification")

    safe_pages = []
    for p in study.get("pages", []):
        sp = {"question": p.get("question", "")}
        if stype == "multiple_choice":
            sp["choices"] = list(p.get("choices", []))
        elif stype == "file_upload":
            sp["instruction"] = p.get("instruction", "")
        safe_pages.append(sp)

    safe_slides = []
    for s in (study.get("slides") or []):
        if isinstance(s, str):
            safe_slides.append({"text": s})
        elif isinstance(s, dict):
            safe_slides.append({"text": s.get("text", "")})

    safe_study = {
        "id": study["id"],
        "title": study["title"],
        "type": stype,
        "mode": study.get("mode", "direct_quiz"),
        "direction": study.get("direction", ""),
        "study_timer": int(study.get("study_timer") or 0),
        "question_timer": int(study.get("question_timer") or 30),
        "max_back": int(study.get("max_back") or 0),
        "mc_options": int(study.get("mc_options") or 0),
        "total_pages": len(safe_pages),
        "pages": safe_pages,
        "score": int(study.get("score") or 0),
        "penalty": int(study.get("penalty") or 0),
        "has_ppt": bool(safe_slides),
        "slides": safe_slides,
    }

    return render_template("student_activity.html",
                           user=actor,
                           study=safe_study,
                           my_id=actor.id)

@app.route("/api/studies/<stid>/cancel", methods=["POST"])
@role_required("Teacher")
def cancel_study(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"ok": False, "error": "Not found"}), 404

    # Kung may content na, huwag delete — hayaan lang as draft
    has_content = any(
        (p.get("question", "") or "").strip()
        for p in study.get("pages", [])
    )
    has_slides = bool(study.get("slides"))

    if has_content or has_slides:
        # May laman — iwan as draft (hindi delete)
        return jsonify({"ok": True, "kept": True})

    # Empty — i-delete
    studies.remove(study)
    return jsonify({"ok": True, "kept": False})

@app.route("/api/studies/<stid>/delete", methods=["POST"])
@role_required("Teacher")
def delete_study(stid):
    actor = current_user()
    study = find_study(stid)
    if not study or study["teacher_id"] != actor.id:
        flash("Not found.", "error")
        return redirect(url_for("teacher_page"))

    # ✅ Optional: block delete kung may attempts (para hindi mawala ang history)
    if study.get("has_attempts"):
        flash("Cannot delete — may student attempts na. Archive na lang.", "error")
        return redirect(url_for("teacher_page"))

    studies.remove(study)
    quiz_results[:] = [r for r in quiz_results if r["study_id"] != stid]
    flash("Study deleted.", "success")
    return redirect(url_for("teacher_page"))

# =====================================================================
# QUIZ
# =====================================================================
@app.route("/api/quiz/submit", methods=["POST"])
@role_required("Student")
def submit_quiz():
    actor = current_user()

    # Accept both JSON (no file) and FormData (with file)
    if request.is_json:
        data = request.get_json()
        study_id = data.get("study_id", "")
        answers = data.get("answers", [])
        total_time = int(data.get("total_time", 0))
        files_map = {}
    else:
        study_id = request.form.get("study_id", "")
        total_time = int(request.form.get("total_time", 0))
        try:
            import json as _json
            meta = _json.loads(request.form.get("answers_meta", "[]"))
        except Exception:
            meta = []

        answers = []
        files_map = {}
        for item in meta:
            i = item.get("idx", 0)
            while len(answers) <= i:
                answers.append(None)
            if item.get("type") == "file":
                answers[i] = item.get("name", "")
                # Save actual file
                key = "file_" + str(i)
                if key in request.files:
                    f = request.files[key]
                    if f and f.filename:
                        safe = secure_filename(f.filename)
                        fname = uuid.uuid4().hex[:8] + "_" + safe
                        path = _os.path.join(UPLOAD_DIR, fname)
                        f.save(path)
                        files_map[i] = {
                            "name": safe,
                            "stored": fname,
                            "url": "/uploads/" + fname,
                        }
            else:
                answers[i] = item.get("value")

    study = find_study(study_id)
    if not study:
        return jsonify({"error": "Study not found."}), 404

    tids = {t.id for t in active_teachers_for_student(actor.id)}
    if study["teacher_id"] not in tids:
        return jsonify({"error": "Not connected to this teacher."}), 403

    if study.get("status") != "published":
        return jsonify({"error": "Study not yet available."}), 400

    already = [r for r in quiz_results
               if r["student_id"] == actor.id and r["study_id"] == study_id]
    if already and not study.get("allow_retry"):
        return jsonify({"error": "Already submitted."}), 400

    pages = study.get("pages", [])
    if not pages:
        return jsonify({"error": "Study has no questions."}), 400

    stype = study.get("type", "identification")
    has_ppt = bool(study.get("slides"))
    study_secs = int(study.get("study_timer") or 0) if (study.get("mode") == "study_and_quiz" and has_ppt) else 3
    min_time = study_secs + int(study.get("question_timer") or 30) * len(pages)
    if total_time and total_time < min_time - 5:
        return jsonify({"error": "Submitted too fast."}), 400

    score_per = int(study.get("score") or 0)
    penalty_per = int(study.get("penalty") or 0)
    total_score = 0
    correct_count = 0
    has_manual = False
    details = []

    for i, p in enumerate(pages):
        ans = answers[i] if i < len(answers) else None
        is_correct = False
        pending = False
        display_your = ans
        display_correct = ""
        file_info = files_map.get(i)

        if stype == "identification":
            ua = (ans or "").strip().lower() if isinstance(ans, str) else ""
            ca = (p.get("correct_answer", "") or "").strip().lower()
            is_correct = bool(ca) and ua == ca
            display_your = ans or ""
            display_correct = p.get("correct_answer", "")

        elif stype == "multiple_choice":
            try: uidx = int(ans) if ans is not None else -1
            except: uidx = -1
            cidx = int(p.get("correct_index", 0))
            is_correct = (uidx == cidx)
            choices = p.get("choices", [])
            letters = ['A','B','C','D']
            display_your = (letters[uidx] + ". " + choices[uidx]) if (0 <= uidx < len(choices)) else "(blank)"
            display_correct = (letters[cidx] + ". " + choices[cidx]) if (0 <= cidx < len(choices)) else ""

        elif stype == "true_false":
            ua = str(ans).lower() if ans is not None else ""
            ca = "true" if p.get("correct_bool", True) else "false"
            is_correct = (ua == ca)
            display_your = "True" if ua == "true" else ("False" if ua == "false" else "(blank)")
            display_correct = "True" if ca == "true" else "False"

        elif stype in ("essay", "file_upload"):
            pending = True
            has_manual = True
            display_your = ans if ans else "(blank)"
            display_correct = "(teacher will grade)"

        if pending:
            pass
        elif is_correct:
            total_score += score_per
            correct_count += 1
        else:
            total_score -= penalty_per

        details.append({
            "idx": i,
            "question": p.get("question", ""),
            "your_answer": display_your,
            "correct_answer": display_correct,
            "correct": is_correct,
            "pending": pending,
            "file": file_info,
        })

    max_score = score_per * len(pages) or 1
    pct = (max(total_score, 0) / max_score) * 100
    medal = calc_medal(pct) if not has_manual else None

    quiz_results.append({
        "id": uuid.uuid4().hex[:8],
        "student_id": actor.id, "student_name": actor.username,
        "study_id": study_id, "study_title": study["title"],
        "answer": str([a if not hasattr(a,'filename') else a.filename for a in answers]),
        "correct": correct_count == len(pages),
        "score": total_score, "medal": medal,
        "correct_count": correct_count,
        "total_questions": len(pages),
        "has_manual": has_manual,
        "graded": not has_manual,
        "details": details,
        "timestamp": now_str(), "adjusted": False,
    })

    # ✅ Mark study as having attempts
    study["has_attempts"] = True

    notify(study["teacher_id"], "Quiz Submitted",
           f"{actor.full_name} submitted '{study['title']}'"
           + (f" — needs grading." if has_manual else f" — {correct_count}/{len(pages)} correct."),
           link="/teacher#history", kind="quiz")

    return jsonify({
        "ok": True,
        "score": total_score,
        "correct_count": correct_count,
        "total": len(pages),
        "medal": medal,
        "has_manual": has_manual,
        "details": details,
    })


@app.route("/api/results/<rid>/update", methods=["POST"])
@role_required("Teacher")
def update_result(rid):
    actor = current_user()
    result = next((r for r in quiz_results if r["id"] == rid), None)
    if not result:
        flash("Result not found.", "error")
        return redirect(url_for("teacher_page"))
    study = find_study(result["study_id"])
    if not study or study["teacher_id"] != actor.id:
        flash("Not your study.", "error")
        return redirect(url_for("teacher_page"))
    try:
        new_score = int(request.form.get("score", result["score"]))
    except ValueError:
        flash("Number required.", "error")
        return redirect(url_for("teacher_page"))
    result["score"] = new_score
    result["adjusted"] = True
    max_score = study["score"] if study["score"] > 0 else 1
    pct = (max(new_score, 0) / max_score) * 100
    result["medal"] = calc_medal(pct) if result["correct"] else None
    notify(result["student_id"], "Score Adjusted",
           f"Your score for '{study['title']}' was updated to {new_score}.",
           link="/student#history", kind="score")
    flash("Score updated.", "success")
    return redirect(url_for("teacher_page"))


# =====================================================================
# ATTENDANCE
# =====================================================================
@app.route("/api/attendance/mark", methods=["POST"])
@role_required("Teacher")
def mark_attendance():
    actor = current_user()
    student_id = request.form.get("student_id", "")
    status = request.form.get("status", "Present")
    date = request.form.get("date") or today_str()
    student = find_user_by_id(student_id)
    if not student or student.role != "Student":
        flash("Invalid student.", "error")
        return redirect(url_for("teacher_page"))
    if not any(c["student_id"] == student_id and c["teacher_id"] == actor.id
               and c["status"] == "active" for c in connections):
        flash("Not connected to this student.", "error")
        return redirect(url_for("teacher_page"))
    if status not in ("Present", "Absent", "Late"):
        flash("Invalid status.", "error")
        return redirect(url_for("teacher_page"))
    existing = next((a for a in attendance
                     if a["student_id"] == student_id
                     and a["date"] == date
                     and a["teacher_id"] == actor.id), None)
    if existing:
        existing["status"] = status
        existing["timestamp"] = now_str()
    else:
        attendance.append({
            "id": uuid.uuid4().hex[:8],
            "student_id": student_id, "student_name": student.username,
            "teacher_id": actor.id, "teacher_name": actor.username,
            "date": date, "status": status, "timestamp": now_str(),
        })
    flash(f"Attendance recorded for {student.username}.", "success")
    return redirect(url_for("teacher_page"))


@app.route("/api/attendance/<aid>/update", methods=["POST"])
@role_required("Teacher")
def update_attendance(aid):
    actor = current_user()
    rec = next((a for a in attendance if a["id"] == aid), None)
    if not rec or rec["teacher_id"] != actor.id:
        flash("Not found.", "error")
        return redirect(url_for("teacher_page"))
    status = request.form.get("status", "")
    if status not in ("Present", "Absent", "Late"):
        flash("Invalid status.", "error")
        return redirect(url_for("teacher_page"))
    rec["status"] = status
    rec["timestamp"] = now_str()
    flash("Attendance updated.", "success")
    return redirect(url_for("teacher_page"))


@app.route("/api/attendance/<aid>/delete", methods=["POST"])
@role_required("Teacher")
def delete_attendance(aid):
    actor = current_user()
    rec = next((a for a in attendance if a["id"] == aid), None)
    if not rec or rec["teacher_id"] != actor.id:
        flash("Not found.", "error")
        return redirect(url_for("teacher_page"))
    attendance.remove(rec)
    flash("Attendance deleted.", "success")
    return redirect(url_for("teacher_page"))

@app.route("/api/results/<rid>/grade-info")
@role_required("Teacher")
def grade_info(rid):
    actor = current_user()
    result = next((r for r in quiz_results if r["id"] == rid), None)
    if not result:
        return jsonify({"error": "Result not found."}), 404
    study = find_study(result["study_id"])
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"error": "Not your study."}), 403
    return jsonify({
        "id": result["id"],
        "student_name": result.get("student_name", ""),
        "study_title": result.get("study_title", ""),
        "study_type": study.get("type", ""),
        "details": result.get("details", []),
        "graded": result.get("graded", True),
        "score": result.get("score", 0),
    })


@app.route("/api/results/<rid>/grade", methods=["POST"])
@role_required("Teacher")
def grade_result(rid):
    actor = current_user()
    result = next((r for r in quiz_results if r["id"] == rid), None)
    if not result:
        return jsonify({"error": "Result not found."}), 404
    study = find_study(result["study_id"])
    if not study or study["teacher_id"] != actor.id:
        return jsonify({"error": "Not your study."}), 403

    data = request.get_json() or {}
    scores = data.get("scores", [])
    score_map = {s["idx"]: int(s["score"]) for s in scores}

    total = 0
    details = result.get("details", [])
    correct_count = 0

    for i, d in enumerate(details):
        if i in score_map:
            awarded = score_map[i]
            d["awarded_score"] = awarded
            d["correct"] = (awarded > 0)
            d["pending"] = False
            total += awarded
            if awarded > 0:
                correct_count += 1

    result["details"] = details
    result["score"] = total
    result["graded"] = True
    result["adjusted"] = True
    result["correct_count"] = correct_count

    max_score = int(study.get("score") or 1) * len(details) or 1
    pct = (max(total, 0) / max_score) * 100
    result["medal"] = calc_medal(pct) if total > 0 else None
    result["correct"] = (correct_count == len(details))

    notify(result["student_id"], "📝 Quiz Graded",
           f"Your submission for '{study['title']}' has been graded. Score: {total}.",
           link="/student#history", kind="score")

    return jsonify({"ok": True, "score": total, "medal": result["medal"]})

@app.route("/uploads/<fname>")
@role_required("Teacher", "Student", "SuperAdmin")
def serve_upload(fname):
    from flask import send_from_directory
    # Sanitize
    fname = secure_filename(fname)
    return send_from_directory(UPLOAD_DIR, fname)

# =====================================================================
# LEADERBOARD API
# =====================================================================
@app.route("/api/leaderboard")
def api_leaderboard():
    u = current_user()
    if not u:
        return jsonify([])
    return jsonify(build_leaderboard())



# =====================================================================
# ERRORS / RUN
# =====================================================================
@app.errorhandler(404)
def nf(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Endpoint not found."}), 404
    return render_template("login.html"), 404


@app.errorhandler(500)
def se(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Server error."}), 500
    return "<h1 style='color:#fff;background:#111;padding:2rem'>500 Error</h1>", 500

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=10000, debug=False)