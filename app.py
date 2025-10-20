# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_caching import Cache
from tmdb import trending, details, search, img_url
from sqlalchemy import UniqueConstraint
import os
from datetime import datetime

# --- вспомогательная функция ---
def parse_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def as_int(s, default=1):
    try:
        v = int(s)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default

app = Flask(__name__)

cache = Cache(app, config={"CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 300})
# === Настройки ===
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///movietracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'diealready')  # в проде ОБЯЗАТЕЛЬНО переопред.

db = SQLAlchemy(app)

# === Модели ===
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_url = db.Column(db.String(255), nullable=True)

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

# === TMDB ===
class UserMedia(db.Model):
    __tablename__ = "user_media"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    media_type = db.Column(db.String(10), nullable=False)
    tmdb_id = db.Column(db.Integer, nullable=False, index=True)

    rating = db.Column(db.Integer)   # 1..10
    progress = db.Column(db.Integer)
    note = db.Column(db.Text)
    status = db.Column(db.String(20))  # planned/watching/completed/dropped

    __table_args__ = (
        UniqueConstraint('user_id', 'media_type', 'tmdb_id', name='uq_user_media_unique'),
    )


# === Flask-Login ===
login_manager = LoginManager(app)
login_manager.login_view = "login"          # куда редиректить неавторизованных
login_manager.login_message = "Войдите, чтобы продолжить."

@app.template_filter('dt')
def format_dt(value):
    return value.strftime("%d.%m.%Y") if value else ""

@app.route("/profile", methods=["GET"])
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = (request.form.get("password") or "").strip()
        avatar = request.form.get("avatar_url") or ""

        # Проверка логина
        if not username:
            flash("Имя пользователя не может быть пустым.", "error")
            return redirect(url_for("edit_profile"))

        # Дубликаты
        existing = User.query.filter(User.username == username, User.id != current_user.id).first()
        if existing:
            flash("Такое имя уже занято.", "error")
            return redirect(url_for("edit_profile"))

        if email:
            existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing_email:
                flash("Этот email уже используется.", "error")
                return redirect(url_for("edit_profile"))

        # Обновляем поля
        current_user.username = username
        current_user.email = email if email else None
        current_user.avatar_url = avatar if avatar else current_user.avatar_url
        if password:
            current_user.set_password(password)

        db.session.commit()
        flash("Профиль успешно обновлён!", "success")
        return redirect(url_for("profile"))

    return render_template("edit_profile.html", user=current_user)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# === Маршруты ===
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower() or None
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        # Простейшая валидация
        if not username or not password:
            flash("Логин и пароль обязательны.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Пароли не совпадают.", "error")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Такой логин уже занят.", "error")
            return render_template("register.html")

        if email and User.query.filter_by(email=email).first():
            flash("Этот email уже используется.", "error")
            return render_template("register.html")

        # Создаём пользователя
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Автовход после регистрации
        login_user(user)
        flash("Регистрация прошла успешно!", "success")
        return redirect(url_for("index"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_field = (request.form.get("login") or "").strip()
        password = request.form.get("password") or ""

        # Позволяем входить по логину ИЛИ email
        user = User.query.filter(
            (User.username == login_field) | (User.email == login_field)
        ).first()

        if not user or not user.check_password(password):
            flash("Неверные данные для входа.", "error")
            return render_template("login.html")

        login_user(user, remember=bool(request.form.get("remember")))
        flash("С возвращением!", "success")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    return render_template("login.html")

@app.route("/start")
def start():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    # гость → на логин; после входа вернём в профиль
    return redirect(url_for("login", next=url_for("profile")))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта.", "success")
    return redirect(url_for("index"))

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')  # ОСНОВНАЯ СТРАНИЦА

def _as_int(s, default=1):
    try:
        v = int(s)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default

@app.route("/catalog")
def catalog():
    # Нормализуем тип (разрешаем только all/movie/tv)
    mtype = (request.args.get("type", "all") or "all").lower()
    if mtype not in {"all", "movie", "tv"}:
        mtype = "all"

    # Безопасно парсим страницу
    page = _as_int(request.args.get("page"), 1)

    cache_key = f"trending:{mtype}:{page}"
    data = cache.get(cache_key)

    if data is None:
        try:
            data = trending(mtype, "week", page)  # tmdb.trending(...)
            # Подстраховка: ожидаем dict с "results" (list)
            if not isinstance(data, dict) or "results" not in data:
                raise ValueError("TMDB trending returned unexpected payload")
            cache.set(cache_key, data)
        except Exception as e:
            # Логируем подробности в консоль/лог и показываем фолбэк
            app.logger.exception("Ошибка в /catalog при вызове trending(%s, week, %s): %s", mtype, page, e)
            flash("Не удалось загрузить тренды. Попробуйте обновить страницу позже.", "error")
            data = {"results": []}

    # Строим элементы каталога — максимально терпимо к None
    items = []
    for it in data.get("results", []) or []:
        try:
            mtype_i = it.get("media_type") or ("movie" if "title" in it else "tv")
            items.append({
                "media_type": mtype_i,
                "tmdb_id": it.get("id"),
                "title": it.get("title") or it.get("name") or "Без названия",
                "poster": img_url(it.get("poster_path"), "w342"),
                "rating": it.get("vote_average"),
                "year": (it.get("release_date") or it.get("first_air_date") or "")[:4],
            })
        except Exception:
            # Если вдруг попался кривой элемент — пропускаем, но не валимся
            continue

    return render_template("catalog.html", items=items, page=page, mtype=mtype)


@app.route("/search")
def search_page():
    q = request.args.get("q", "").strip()
    page = int(request.args.get("page", 1))
    data = search(q, "multi", page) if q else {"results":[]}
    items = []
    for it in data.get("results", []):
        mtype_i = it.get("media_type")
        if mtype_i not in ("movie", "tv"):  # пропускаем персон и т.п.
            continue
        items.append({
            "media_type": mtype_i,
            "tmdb_id": it["id"],
            "title": it.get("title") or it.get("name"),
            "poster": img_url(it.get("poster_path"), "w185"),
            "desc": it.get("overview")
        })
    return render_template("search.html", q=q, items=items, page=page)

@app.route("/title/<media_type>/<int:tmdb_id>", methods=["GET", "POST"])
@login_required
def title_page(media_type, tmdb_id):
    if request.method == "POST":
        # сохранить пользовательские поля
        um = UserMedia.query.filter_by(
            user_id=current_user.id,
            media_type=media_type,
            tmdb_id=tmdb_id
        ).first()
        if not um:
            um = UserMedia(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id)
            db.session.add(um)

        # --- безопасная обработка данных из формы ---
        def parse_int(value, default=None):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        raw_rating = request.form.get("rating")
        rating = parse_int(raw_rating)
        if rating is not None and not (1 <= rating <= 10):
            flash("Рейтинг должен быть от 1 до 10.", "error")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        raw_progress = request.form.get("progress")
        progress = parse_int(raw_progress, 0)
        if progress < 0:
            progress = 0

        status = request.form.get("status") or None
        if status and status not in {"planned", "watching", "completed", "dropped"}:
            flash("Некорректный статус.", "error")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        # --- сохраняем ---
        um.rating = rating
        um.progress = progress
        um.status = status
        um.note = request.form.get("note") or None

        db.session.commit()
        flash("Сохранено!", "success")
        return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

    # --- GET-запрос ---
    info = details(media_type, tmdb_id)
    um = UserMedia.query.filter_by(
        user_id=current_user.id,
        media_type=media_type,
        tmdb_id=tmdb_id
    ).first()
    ctx = {
        "media_type": media_type,
        "tmdb_id": tmdb_id,
        "title": info.get("title") or info.get("name"),
        "poster": img_url(info.get("poster_path"), "w342"),
        "backdrop": img_url(info.get("backdrop_path"), "w780"),
        "overview": info.get("overview"),
        "genres": [g["name"] for g in info.get("genres", [])],
        "vote": info.get("vote_average"),
        "year": (info.get("release_date") or info.get("first_air_date") or "")[:4],
        "seasons": info.get("number_of_seasons") if media_type == "tv" else None,
        "episodes": info.get("number_of_episodes") if media_type == "tv" else None,
        "user": um
    }
    return render_template("title.html", **ctx)



@app.route("/my_list")
@login_required
def my_list():
    return render_template('my_list.html')

@app.route("/stats")
@login_required
def stats():
    return render_template('stats.html')



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')