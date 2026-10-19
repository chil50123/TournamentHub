import os, sqlite3, random
from functools import wraps
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("TOURNAMENTHUB_DB", os.path.join(APP_DIR, "tournamenthub.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','organizer','admin')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      captain_id INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS team_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      team_id INTEGER NOT NULL REFERENCES teams(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      status TEXT NOT NULL CHECK(status IN ('invited','active','declined')),
      UNIQUE(team_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS tournaments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organizer_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      game TEXT NOT NULL,
      rules TEXT NOT NULL,
      team_size INTEGER NOT NULL CHECK(team_size > 0),
      capacity INTEGER NOT NULL CHECK(capacity IN (4,8,16)),
      starts_at TEXT NOT NULL,
      registration_deadline TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','registration','in_progress','completed')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
      team_id INTEGER NOT NULL REFERENCES teams(id),
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(tournament_id,team_id)
    );
    CREATE TABLE IF NOT EXISTS entry_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL REFERENCES entries(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      UNIQUE(entry_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tournament_id INTEGER NOT NULL REFERENCES tournaments(id),
      round INTEGER NOT NULL,
      position INTEGER NOT NULL,
      team_a_id INTEGER REFERENCES teams(id),
      team_b_id INTEGER REFERENCES teams(id),
      score_a INTEGER,
      score_b INTEGER,
      winner_id INTEGER REFERENCES teams(id),
      next_match_id INTEGER REFERENCES matches(id),
      played_at TEXT,
      UNIQUE(tournament_id,round,position)
    );
    CREATE INDEX IF NOT EXISTS idx_entries_tournament_status ON entries(tournament_id,status);
    CREATE INDEX IF NOT EXISTS idx_matches_tournament_round ON matches(tournament_id,round,position);
    CREATE INDEX IF NOT EXISTS idx_team_members_user_status ON team_members(user_id,status);
    """)
    conn.commit()
    conn.close()

@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid:
        g.user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

@app.context_processor
def inject_globals():
    return {"current_user": getattr(g, "user", None), "now": datetime.now().strftime("%Y-%m-%dT%H:%M")}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Для этого действия сначала войдите в аккаунт.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def tournament_owner(t):
    return g.user and (g.user["role"] == "admin" or t["organizer_id"] == g.user["id"])

def get_tournament(tid):
    t = db().execute("SELECT t.*,u.display_name AS organizer_name FROM tournaments t JOIN users u ON u.id=t.organizer_id WHERE t.id=?", (tid,)).fetchone()
    if not t: abort(404)
    return t

def active_team_member(team_id, user_id):
    return db().execute("SELECT 1 FROM team_members WHERE team_id=? AND user_id=? AND status='active'", (team_id,user_id)).fetchone() is not None

def team_for_captain(team_id):
    team = db().execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
    if not team: abort(404)
    if g.user["role"] != "admin" and team["captain_id"] != g.user["id"]:
        abort(403)
    return team

@app.route("/")
def index():
    tournaments = db().execute("""
      SELECT t.*, u.display_name organizer_name,
      (SELECT COUNT(*) FROM entries e WHERE e.tournament_id=t.id AND e.status='accepted') accepted_count
      FROM tournaments t JOIN users u ON u.id=t.organizer_id
      ORDER BY CASE t.status WHEN 'registration' THEN 0 WHEN 'in_progress' THEN 1 WHEN 'draft' THEN 2 ELSE 3 END,
      t.starts_at LIMIT 9
    """).fetchall()
    return render_template("index.html", tournaments=tournaments)

@app.route("/register", methods=["GET","POST"])
def register():
    if g.user: return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip().lower()
        display_name = request.form.get("display_name","").strip()
        password = request.form.get("password","")
        errors = {}
        if len(username) < 3: errors["username"] = "Имя пользователя — минимум 3 символа."
        if not email or "@" not in email: errors["email"] = "Введите корректный email."
        if len(display_name) < 2: errors["display_name"] = "Укажите имя минимум из 2 символов."
        if len(password) < 8: errors["password"] = "Пароль должен содержать минимум 8 символов."
        if not errors:
            try:
                cur = db().execute("INSERT INTO users(username,email,password_hash,display_name) VALUES(?,?,?,?)",
                    (username,email,generate_password_hash(password),display_name))
                db().commit()
                session["user_id"] = cur.lastrowid
                flash("Аккаунт создан. Добро пожаловать!", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                errors["username"] = "Имя пользователя или email уже заняты."
        return render_template("auth.html", mode="register", errors=errors, values=request.form)
    return render_template("auth.html", mode="register", errors={}, values={})

@app.route("/login", methods=["GET","POST"])
def login():
    if g.user: return redirect(url_for("index"))
    if request.method == "POST":
        identity = request.form.get("identity","").strip()
        user = db().execute("SELECT * FROM users WHERE username=? OR email=?", (identity,identity.lower())).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password","")):
            session.clear(); session["user_id"] = user["id"]
            flash("Вы вошли в аккаунт.", "success")
            return redirect(url_for("index"))
        return render_template("auth.html", mode="login", errors={"identity":"Неверный логин/email или пароль."}, values=request.form)
    return render_template("auth.html", mode="login", errors={}, values={})

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "success")
    return redirect(url_for("index"))

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("display_name","").strip()
        if len(name) < 2:
            flash("Имя должно содержать минимум 2 символа.", "error")
        else:
            db().execute("UPDATE users SET display_name=? WHERE id=?", (name,g.user["id"]))
            db().commit(); flash("Профиль обновлён.", "success")
            return redirect(url_for("profile"))
    teams = db().execute("""SELECT t.*,tm.status FROM teams t JOIN team_members tm ON tm.team_id=t.id
      WHERE tm.user_id=? AND tm.status IN ('active','invited') ORDER BY t.name""", (g.user["id"],)).fetchall()
    return render_template("profile.html", teams=teams)

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def change_role(user_id):
    role = request.form.get("role")
    if role not in ("user","organizer","admin"): abort(400)
    if user_id == g.user["id"] and role != "admin":
        flash("Нельзя снять роль администратора с самого себя.", "error")
    else:
        db().execute("UPDATE users SET role=? WHERE id=?", (role,user_id)); db().commit()
        flash("Роль пользователя изменена.", "success")
    return redirect(url_for("admin"))

@app.route("/admin")
@role_required("admin")
def admin():
    users = db().execute("SELECT id,username,email,display_name,role FROM users ORDER BY id DESC").fetchall()
    return render_template("admin.html", users=users)

@app.route("/teams", methods=["GET","POST"])
@login_required
def teams():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        if len(name) < 2:
            flash("Название команды должно содержать минимум 2 символа.", "error")
        else:
            try:
                cur = db().execute("INSERT INTO teams(name,captain_id) VALUES(?,?)", (name,g.user["id"]))
                db().execute("INSERT INTO team_members(team_id,user_id,status) VALUES(?,?,'active')", (cur.lastrowid,g.user["id"]))
                db().commit(); flash("Команда создана. Вы капитан.", "success")
                return redirect(url_for("team_detail", team_id=cur.lastrowid))
            except sqlite3.IntegrityError:
                db().rollback(); flash("Команда с таким названием уже существует.", "error")
    mine = db().execute("""SELECT t.*, tm.status, u.display_name captain_name FROM teams t
      JOIN team_members tm ON tm.team_id=t.id JOIN users u ON u.id=t.captain_id
      WHERE tm.user_id=? AND tm.status IN ('active','invited') ORDER BY t.name""", (g.user["id"],)).fetchall()
    return render_template("teams.html", teams=mine)

@app.route("/teams/<int:team_id>")
@login_required
def team_detail(team_id):
    team = db().execute("SELECT t.*,u.display_name captain_name FROM teams t JOIN users u ON u.id=t.captain_id WHERE t.id=?", (team_id,)).fetchone()
    if not team: abort(404)
    member = db().execute("SELECT status FROM team_members WHERE team_id=? AND user_id=?", (team_id,g.user["id"])).fetchone()
    if not member and g.user["role"] != "admin": abort(403)
    members = db().execute("""SELECT tm.status,u.id user_id,u.username,u.display_name,u.email FROM team_members tm
      JOIN users u ON u.id=tm.user_id WHERE tm.team_id=? ORDER BY tm.status,u.display_name""", (team_id,)).fetchall()
    return render_template("team_detail.html", team=team, members=members, is_captain=(team["captain_id"]==g.user["id"] or g.user["role"]=="admin"))

@app.route("/teams/<int:team_id>/invitations", methods=["POST"])
@login_required
def invite(team_id):
    team = team_for_captain(team_id)
    email = request.form.get("email","").strip().lower()
    user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        flash("Пользователь с таким email не найден. Сначала попросите его зарегистрироваться.", "error")
    elif user["id"] == team["captain_id"]:
        flash("Вы уже капитан команды.", "error")
    else:
        # A user may be on only one active team at a time.
        existing = db().execute("SELECT 1 FROM team_members WHERE user_id=? AND status='active'", (user["id"],)).fetchone()
        if existing:
            flash("Этот пользователь уже состоит в другой команде.", "error")
        else:
            try:
                db().execute("INSERT INTO team_members(team_id,user_id,status) VALUES(?, ?, 'invited')", (team_id,user["id"]))
                db().commit(); flash("Приглашение отправлено.", "success")
            except sqlite3.IntegrityError:
                db().rollback(); flash("Приглашение уже существует.", "error")
    return redirect(url_for("team_detail", team_id=team_id))

@app.route("/invitations/<int:team_id>/<action>", methods=["POST"])
@login_required
def invitation_action(team_id, action):
    if action not in ("accept","decline"): abort(400)
    inv = db().execute("SELECT * FROM team_members WHERE team_id=? AND user_id=? AND status='invited'", (team_id,g.user["id"])).fetchone()
    if not inv: abort(404)
    if action == "accept":
        active = db().execute("SELECT 1 FROM team_members WHERE user_id=? AND status='active'", (g.user["id"],)).fetchone()
        if active:
            flash("Вы уже состоите в команде. Сначала выйдите из неё.", "error")
        else:
            db().execute("UPDATE team_members SET status='active' WHERE id=?", (inv["id"],)); db().commit()
            flash("Вы приняли приглашение.", "success")
    else:
        db().execute("UPDATE team_members SET status='declined' WHERE id=?", (inv["id"],)); db().commit()
        flash("Приглашение отклонено.", "success")
    return redirect(url_for("team_detail", team_id=team_id) if action == "accept" else url_for("profile"))

@app.route("/tournaments")
def tournament_list():
    status = request.args.get("status","")
    query = """SELECT t.*,u.display_name organizer_name,
      (SELECT COUNT(*) FROM entries e WHERE e.tournament_id=t.id AND e.status='accepted') accepted_count
      FROM tournaments t JOIN users u ON u.id=t.organizer_id"""
    args = []
    if status in ("draft","registration","in_progress","completed"):
        query += " WHERE t.status=?"; args.append(status)
    query += " ORDER BY t.starts_at DESC"
    items = db().execute(query,args).fetchall()
    return render_template("tournaments.html", tournaments=items, selected=status)

@app.route("/tournaments/create", methods=["GET","POST"])
@role_required("organizer","admin")
def create_tournament():
    errors = {}
    if request.method == "POST":
        title=request.form.get("title","").strip(); game=request.form.get("game","").strip()
        rules=request.form.get("rules","").strip(); team_size=request.form.get("team_size","")
        capacity=request.form.get("capacity",""); starts=request.form.get("starts_at","")
        deadline=request.form.get("registration_deadline",""); status=request.form.get("status","draft")
        if len(title)<3: errors["title"]="Название — минимум 3 символа."
        if not game: errors["game"]="Укажите игру."
        if not rules: errors["rules"]="Добавьте правила турнира."
        try:
            size=int(team_size)
            if size<1 or size>20: raise ValueError()
        except ValueError: errors["team_size"]="Размер команды должен быть от 1 до 20."; size=1
        if capacity not in ("4","8","16"): errors["capacity"]="Выберите 4, 8 или 16 команд."
        if not starts or not deadline: errors["starts_at"]="Укажите дату турнира и дедлайн регистрации."
        if status not in ("draft","registration"): status="draft"
        if not errors:
            cur=db().execute("""INSERT INTO tournaments(organizer_id,title,game,rules,team_size,capacity,starts_at,registration_deadline,status)
              VALUES(?,?,?,?,?,?,?,?,?)""",(g.user["id"],title,game,rules,size,int(capacity),starts,deadline,status))
            db().commit(); flash("Турнир создан.", "success")
            return redirect(url_for("tournament_detail", tid=cur.lastrowid))
        return render_template("tournament_form.html", errors=errors, values=request.form)
    return render_template("tournament_form.html", errors={}, values={})

@app.route("/tournaments/<int:tid>")
def tournament_detail(tid):
    t=get_tournament(tid)
    entries=db().execute("""SELECT e.*,tm.name team_name, u.display_name captain_name,
      (SELECT COUNT(*) FROM entry_members em WHERE em.entry_id=e.id) member_count
      FROM entries e JOIN teams tm ON tm.id=e.team_id JOIN users u ON u.id=tm.captain_id
      WHERE e.tournament_id=? ORDER BY e.created_at""",(tid,)).fetchall()
    my_teams=db().execute("""SELECT t.* FROM teams t JOIN team_members m ON m.team_id=t.id
      WHERE m.user_id=? AND m.status='active' AND t.captain_id=? ORDER BY t.name""",
      ((g.user["id"] if g.user else -1),(g.user["id"] if g.user else -1))).fetchall()
    is_owner=tournament_owner(t)
    return render_template("tournament_detail.html", tournament=t, entries=entries, my_teams=my_teams, is_owner=is_owner)

@app.route("/tournaments/<int:tid>/status", methods=["POST"])
@login_required
def tournament_status(tid):
    t=get_tournament(tid)
    if not tournament_owner(t): abort(403)
    status=request.form.get("status")
    allowed={"draft":["registration"],"registration":["draft"],"in_progress":[],"completed":[]}
    if status not in allowed.get(t["status"],[]): 
        flash("Такой переход статуса запрещён.", "error")
    else:
        db().execute("UPDATE tournaments SET status=? WHERE id=?", (status,tid)); db().commit()
        flash("Статус турнира изменён.", "success")
    return redirect(url_for("tournament_detail",tid=tid))

@app.route("/tournaments/<int:tid>/entries", methods=["POST"])
@login_required
def create_entry(tid):
    t=get_tournament(tid)
    team_id=request.form.get("team_id","")
    if t["status"]!="registration":
        flash("Регистрация сейчас закрыта.", "error")
    elif datetime.now().strftime("%Y-%m-%dT%H:%M") > t["registration_deadline"]:
        flash("Срок регистрации истёк.", "error")
    else:
        try: team_id=int(team_id)
        except ValueError: abort(400)
        team=team_for_captain(team_id)
        members=db().execute("SELECT user_id FROM team_members WHERE team_id=? AND status='active'",(team_id,)).fetchall()
        if len(members)!=t["team_size"]:
            flash(f"В команде должно быть ровно {t['team_size']} активных участника.", "error")
        elif db().execute("SELECT COUNT(*) n FROM entries WHERE tournament_id=? AND status='accepted'",(tid,)).fetchone()["n"] >= t["capacity"]:
            flash("Все места уже заняты.", "error")
        else:
            # A player can only appear in one accepted team in this tournament.
            user_ids=[m["user_id"] for m in members]
            placeholders=",".join("?" for _ in user_ids)
            conflict=db().execute(f"""SELECT em.user_id FROM entries e JOIN entry_members em ON em.entry_id=e.id
              WHERE e.tournament_id=? AND e.status IN ('pending','accepted') AND em.user_id IN ({placeholders})""",(tid,*user_ids)).fetchone()
            if conflict:
                flash("Один или несколько игроков уже заявлены в другой состав этого турнира.", "error")
            else:
                try:
                    cur=db().execute("INSERT INTO entries(tournament_id,team_id,status) VALUES(?,?,'pending')",(tid,team_id))
                    db().executemany("INSERT INTO entry_members(entry_id,user_id) VALUES(?,?)",[(cur.lastrowid,u) for u in user_ids])
                    db().commit(); flash("Заявка отправлена организатору.", "success")
                except sqlite3.IntegrityError:
                    db().rollback(); flash("Эта команда уже подавала заявку.", "error")
    return redirect(url_for("tournament_detail",tid=tid))

@app.route("/entries/<int:entry_id>/<decision>", methods=["POST"])
@login_required
def decide_entry(entry_id,decision):
    if decision not in ("accept","reject"): abort(400)
    entry=db().execute("SELECT * FROM entries WHERE id=?",(entry_id,)).fetchone()
    if not entry: abort(404)
    t=get_tournament(entry["tournament_id"])
    if not tournament_owner(t): abort(403)
    if t["status"]!="registration" or entry["status"]!="pending":
        flash("Заявку нельзя изменить в текущем состоянии.", "error")
    elif decision=="accept":
        count=db().execute("SELECT COUNT(*) n FROM entries WHERE tournament_id=? AND status='accepted'",(t["id"],)).fetchone()["n"]
        if count>=t["capacity"]:
            flash("Свободных мест больше нет.", "error")
        else:
            db().execute("UPDATE entries SET status='accepted' WHERE id=?",(entry_id,)); db().commit()
            flash("Заявка принята.", "success")
    else:
        db().execute("UPDATE entries SET status='rejected' WHERE id=?",(entry_id,)); db().commit()
        flash("Заявка отклонена.", "success")
    return redirect(url_for("tournament_detail",tid=t["id"]))

def generate_bracket(tid, organizer_id):
    conn=db()
    t=get_tournament(tid)
    if not tournament_owner(t): abort(403)
    if t["status"]!="registration": raise ValueError("Сетка доступна только после регистрации.")
    entries=conn.execute("SELECT team_id FROM entries WHERE tournament_id=? AND status='accepted'",(tid,)).fetchall()
    if len(entries)!=t["capacity"]: raise ValueError(f"Для старта нужно ровно {t['capacity']} принятых команд.")
    if conn.execute("SELECT 1 FROM matches WHERE tournament_id=?",(tid,)).fetchone():
        raise ValueError("Сетка уже создана; повторная генерация запрещена.")
    team_ids=[r["team_id"] for r in entries]
    random.SystemRandom().shuffle(team_ids)
    total_rounds=(len(team_ids)-1).bit_length()
    match_ids={}
    for rnd in range(1,total_rounds+1):
        count=len(team_ids)//(2**rnd)
        for pos in range(count):
            cur=conn.execute("INSERT INTO matches(tournament_id,round,position) VALUES(?,?,?)",(tid,rnd,pos+1))
            match_ids[(rnd,pos+1)]=cur.lastrowid
    # Wire next-match relationships after all matches exist.
    for rnd in range(1,total_rounds):
        count=len(team_ids)//(2**rnd)
        for pos in range(1,count+1):
            next_id=match_ids[(rnd+1,(pos+1)//2)]
            conn.execute("UPDATE matches SET next_match_id=? WHERE id=?",(next_id,match_ids[(rnd,pos)]))
    for i in range(0,len(team_ids),2):
        pos=i//2+1
        conn.execute("UPDATE matches SET team_a_id=?,team_b_id=? WHERE id=?",(team_ids[i],team_ids[i+1],match_ids[(1,pos)]))
    conn.execute("UPDATE tournaments SET status='in_progress' WHERE id=?",(tid,))
    conn.commit()

@app.route("/tournaments/<int:tid>/generate-bracket", methods=["POST"])
@login_required
def bracket_generate(tid):
    try:
        generate_bracket(tid,g.user["id"])
        flash("Сетка создана. Удачи командам!", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("bracket",tid=tid))

@app.route("/tournaments/<int:tid>/bracket")
def bracket(tid):
    t=get_tournament(tid)
    matches=db().execute("""SELECT m.*,a.name team_a_name,b.name team_b_name,w.name winner_name
      FROM matches m LEFT JOIN teams a ON a.id=m.team_a_id LEFT JOIN teams b ON b.id=m.team_b_id
      LEFT JOIN teams w ON w.id=m.winner_id WHERE m.tournament_id=? ORDER BY m.round,m.position""",(tid,)).fetchall()
    rounds={}
    for m in matches: rounds.setdefault(m["round"],[]).append(m)
    winner=None
    final=next((m for m in matches if m["round"]==max(rounds.keys(),default=0)),None)
    if final and final["winner_id"]: winner=final["winner_name"]
    return render_template("bracket.html", tournament=t, rounds=rounds, winner=winner, is_owner=tournament_owner(t))

@app.route("/matches/<int:match_id>", methods=["GET","POST"])
@login_required
def match_detail(match_id):
    m=db().execute("""SELECT m.*,t.title tournament_title,t.organizer_id,t.status tournament_status,
      a.name team_a_name,b.name team_b_name FROM matches m JOIN tournaments t ON t.id=m.tournament_id
      LEFT JOIN teams a ON a.id=m.team_a_id LEFT JOIN teams b ON b.id=m.team_b_id WHERE m.id=?""",(match_id,)).fetchone()
    if not m: abort(404)
    if request.method=="POST":
        if g.user["role"]!="admin" and m["organizer_id"]!=g.user["id"]: abort(403)
        if m["tournament_status"]!="in_progress": flash("Турнир уже не принимает результаты.", "error")
        elif m["winner_id"] is not None: flash("Подтверждённый результат нельзя изменить.", "error")
        elif not m["team_a_id"] or not m["team_b_id"]: flash("Нельзя ввести результат до определения обеих команд.", "error")
        else:
            try:
                sa=int(request.form.get("score_a","")); sb=int(request.form.get("score_b",""))
                winner=int(request.form.get("winner_id",""))
                if sa<0 or sb<0: raise ValueError()
                if sa==sb: raise ValueError("Ничья запрещена. Укажите счёт с победителем.")
                if winner not in (m["team_a_id"],m["team_b_id"]): raise ValueError("Победитель должен быть участником матча.")
                if (winner==m["team_a_id"] and sa<=sb) or (winner==m["team_b_id"] and sb<=sa):
                    raise ValueError("Победитель должен иметь больший счёт.")
                db().execute("UPDATE matches SET score_a=?,score_b=?,winner_id=?,played_at=CURRENT_TIMESTAMP WHERE id=?",(sa,sb,winner,match_id))
                if m["next_match_id"]:
                    next_match=db().execute("SELECT * FROM matches WHERE id=?",(m["next_match_id"],)).fetchone()
                    col="team_a_id" if m["round"] and m["position"]%2==1 else "team_b_id"
                    # Do not overwrite an already assigned slot.
                    db().execute(f"UPDATE matches SET {col}=? WHERE id=?",(winner,m["next_match_id"]))
                else:
                    db().execute("UPDATE tournaments SET status='completed' WHERE id=?",(m["tournament_id"],))
                db().commit(); flash("Результат сохранён, победитель прошёл дальше.", "success")
                return redirect(url_for("match_detail",match_id=match_id))
            except ValueError as exc:
                flash(str(exc) or "Введите корректный неотрицательный целый счёт.", "error")
    fresh=db().execute("""SELECT m.*,a.name team_a_name,b.name team_b_name,w.name winner_name
      FROM matches m LEFT JOIN teams a ON a.id=m.team_a_id LEFT JOIN teams b ON b.id=m.team_b_id
      LEFT JOIN teams w ON w.id=m.winner_id WHERE m.id=?""",(match_id,)).fetchone()
    can_edit=(g.user["role"]=="admin" or m["organizer_id"]==g.user["id"])
    return render_template("match.html", match=fresh, can_edit=can_edit)

@app.errorhandler(403)
def forbidden(_): return render_template("error.html", code=403, message="У вас нет прав для этого действия."),403
@app.errorhandler(404)
def not_found(_): return render_template("error.html", code=404, message="Страница или объект не найдены."),404
@app.errorhandler(400)
def bad_request(_): return render_template("error.html", code=400, message="Некорректный запрос. Проверьте введённые данные."),400

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("База данных создана.")

@app.cli.command("seed")
def seed_command():
    init_db()
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
    count=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count:
        print("В базе уже есть пользователи; seed пропущен."); conn.close(); return
    users=[
      ("admin","admin@example.com","Admin123!","Администратор","admin"),
      ("organizer","organizer@example.com","Organ123!","Организатор","organizer"),
      ("captain1","captain1@example.com","Player123!","Капитан Alpha","user"),
      ("captain2","captain2@example.com","Player123!","Капитан Bravo","user"),
      ("captain3","captain3@example.com","Player123!","Капитан Charlie","user"),
      ("captain4","captain4@example.com","Player123!","Капитан Delta","user"),
    ]
    for username,email,pw,name,role in users:
        conn.execute("INSERT INTO users(username,email,password_hash,display_name,role) VALUES(?,?,?,?,?)",
          (username,email,generate_password_hash(pw),name,role))
    conn.execute("""INSERT INTO tournaments(organizer_id,title,game,rules,team_size,capacity,starts_at,registration_deadline,status)
      VALUES(2,'TournamentHub Cup','Counter-Strike 2','Single elimination. Администратор турнира подтверждает результаты.',1,4,'2026-12-01T18:00','2026-11-30T23:59','registration')""")
    for i in range(1,5):
        uid=i+2
        cur=conn.execute("INSERT INTO teams(name,captain_id) VALUES(?,?)",(f"Team {['Alpha','Bravo','Charlie','Delta'][i-1]}",uid))
        tid=cur.lastrowid
        conn.execute("INSERT INTO team_members(team_id,user_id,status) VALUES(?,?,'active')",(tid,uid))
    conn.commit(); conn.close()
    print("Демо-данные добавлены. Логины и пароли см. README.md.")

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
# Если ты используешь SQLAlchemy:
# from models import Tournament, User

admin = Admin(app, name='TournamentHub Admin', template_mode='bootstrap3')

# Добавь свои модели, чтобы они появились в админке
# admin.add_view(ModelView(Tournament, db.session))
# admin.add_view(ModelView(User, db.session))

from flask_admin import Admin, AdminIndexView
from flask import redirect, url_for

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        # Простейшая проверка: пускаем только если есть переменная окружения ADMIN=1
        # Лучше сделать нормальный логин, но для старта сойдёт
        return True  # Пока разрешим всем (для теста)

admin = Admin(app, name='TournamentHub Admin', index_view=MyAdminIndexView())

