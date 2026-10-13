# 🎓 Multi-School E-Learning Management System

A complete **Flask + Python OOP** e-learning platform that supports **multiple
schools** (CKCM, MSU, Xavier, and any other school created by the Super Admin).

The system uses **Python lists only** — no database, no SQLAlchemy, no SQLite,
no MySQL, no MongoDB, no Firebase.

---

## 1. Project Title

**Multi-School E-Learning Management System**
*(Default example school: CKCM — but the system is NOT hardcoded to CKCM.)*

---

## 2. Project Description

The system is a multi-tenant e-learning platform where a **Super Admin**
creates schools, each school is managed by a **School Admin**, teachers create
**studies** with a **countdown timer** and a **quiz**, and students study, answer
quizzes, earn **medals**, appear on a **school leaderboard**, get **attendance**
records, and rate their **teachers**.

All data is stored in in-memory Python lists, so the system is **real-time**
and completely database-free.

---

## 3. Roles

| Role | Scope | Main Responsibilities |
|------|-------|-----------------------|
| **SuperAdmin** | Global | Create / Update / Delete schools; create School Admins; view all users, studies, results, attendance and votes |
| **SchoolAdmin** | One school | Approve/Reject pending Teacher & Student signups; add/remove users; edit school info; view leaderboard, attendance, quiz results, teacher ratings |
| **Teacher** | One school | CRUD studies (title, content, timer, quiz, correct answer, score, penalty); view quiz history; adjust scores; mark attendance |
| **Student** | One school | Study (modal with timer), take quizzes after timer ends, view medals, attendance, leaderboard, rate teachers |

### Rubric mapping — the 3 user categories

| Instructor's 3 categories | Our roles |
|---------------------------|-----------|
| **ADMIN** | `SuperAdmin` (system-level owner) + `SchoolAdmin` (school-level) |
| **TEACHER / STAFF** | `Teacher` |
| **STUDENT / MEMBER** | `Student` |

Super Admin is the **system owner**, while School Admin / Teacher / Student are
the **operational users** — this satisfies both the instructor's 3-role
requirement and the richer e-learning feature set.

---

## 4. Features

- ✅ **Login with 4 fields** (username, password, role, school) with full validation
- ✅ **Role-based dashboards** (Super Admin / School Admin / Teacher / Student)
- ✅ **School CRUD** (Super Admin only creates; School Admin edits own school)
- ✅ **User CRUD** (create / read / update via approval / delete)
- ✅ **Studies CRUD** (Teacher)
- ✅ **Pending approval system** for Teacher/Student signups
- ✅ **Study modal with countdown timer** — quiz unlocks only when timer hits 00:00
- ✅ **Quiz scoring** with correct score / wrong-answer penalty
- ✅ **Automatic medals** (Gold ≥ 90%, Silver 75–89%, Bronze 60–74%)
- ✅ **Teacher score adjustment** (affects leaderboard immediately)
- ✅ **Attendance** (Present / Absent / Late) with update & delete
- ✅ **Teacher rating** (1–5 stars, one vote per student, updateable)
- ✅ **School leaderboard** ranked by total quiz points
- ✅ **Profiles** for students, teachers, admins and schools
- ✅ **Real-time polling** for leaderboard and pending requests
- ✅ **Modals for everything** — no unnecessary page navigation
- ✅ **Dark, responsive, modern UI** (CSS + JS entirely in `base.html`)
ito na yung flow setting modal diba may select drop down identification , multiple choice, T and F ,essay no auto check teacher grades manualy, and file upload so like pag mag select si teacher ng multiple choice ganito ang form modal nya pages tas may select dropdown na para sa direct quiz or study muna and quiz, pag pinili ni teacher yung may study muna and quiz lalabas yung timer or study time tas pili si teacher time and pag next -> makita doon sa activity.html yung upload study pwede docs ppt or any documents and title direction question  parasa sa lahat yan na quiz type at doon sa multiple choice pag pinili ni teacher yung multiple choice sa dropdown mag iba yung design or inputs depende kung anong klasi ang quiz like sa multiple choice so sa modal form nya ay pages tas may select dropdown na para sa direct quiz or study muna and quiz and may two option na dot kung a b c d or a b c pag abc yung pinili sa dot so yung pag next abc lang so sa ibang quiz type ikaw na bahala paano gawin gayahin mona lang yung sa iba like sa google clasroom pero same padin yung gusto ko yung inotos ko create mona at dapat responsive at gumana 
---


## 5. OOP Concepts — Where They Are Demonstrated

### 🔒 Encapsulation — `app.py`
```python
class User:
    def __init__(self, username, password, role, ...):
        self.__password = password          # private (name-mangled)

    def check_password(self, password):
        return self.__password == password  # controlled access

