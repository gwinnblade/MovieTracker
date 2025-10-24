# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_caching import Cache
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import UniqueConstraint
import uuid
from datetime import datetime
from tmdb import trending, details, search, img_url
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

# === Uploads ===
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 2 МБ — лимит на файл
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Убедимся, что папка есть
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS

def unique_filename(filename: str) -> str:
    # сохраняем безопасное имя + добавляем UUID
    base = secure_filename(filename)
    ext = (base.rsplit('.', 1)[-1].lower() if '.' in base else 'jpg')
    return f"{uuid.uuid4().hex}.{ext}"

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

class EpisodeNote(db.Model):
    __tablename__ = "episode_note"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    tv_id = db.Column(db.Integer, nullable=False, index=True)  # TMDB id сериала
    season = db.Column(db.Integer, nullable=False)
    episode = db.Column(db.Integer, nullable=False)

    note = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "tv_id", "season", "episode", name="uq_user_tv_season_episode"),
    )


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

    seasons_watched  = db.Column(db.Integer)  # для TV
    episodes_watched = db.Column(db.Integer)  # для TV

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

@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    flash("Файл слишком большой. Максимум 2 МБ.", "error")
    return redirect(url_for("edit_profile"))

@app.route("/profile", methods=["GET"])
@login_required
def profile():
    # Все записи пользователя
    base_q = UserMedia.query.filter_by(user_id=current_user.id)

    # Подсчёты
    movies_completed = base_q.filter(
        UserMedia.media_type == "movie",
        UserMedia.status == "completed"
    ).count()

    tv_completed = base_q.filter(
        UserMedia.media_type == "tv",
        UserMedia.status == "completed"
    ).count()

    total_titles = base_q.count()

    # Последние 3 завершённых (по id как суррогат «даты добавления/обновления»)
    recent = base_q.filter(UserMedia.status == "completed") \
                   .order_by(UserMedia.id.desc()) \
                   .limit(3).all()

    # Гидратация карточек
    recent_items = []
    for um in recent:
        try:
            info = details(um.media_type, um.tmdb_id)
            recent_items.append({
                "title": info.get("title") or info.get("name") or "Без названия",
                "year": (info.get("release_date") or info.get("first_air_date") or "")[:4],
                "poster": img_url(info.get("poster_path"), "w200"),
                "href": url_for("title_page", media_type=um.media_type, tmdb_id=um.tmdb_id),
                "rating_user": um.rating,
                "note": um.note,
            })
        except Exception:
            # Если TMDB вернул ошибку — пропустим элемент
            continue

    return render_template(
        "profile.html",
        user=current_user,
        total_titles=total_titles,
        movies_completed=movies_completed,
        tv_completed=tv_completed,
        recent_items=recent_items
    )

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = (request.form.get("password") or "").strip()

        # 1) базовая валидация
        if not username:
            flash("Имя пользователя не может быть пустым.", "error")
            return redirect(url_for("edit_profile"))

        existing = User.query.filter(User.username == username, User.id != current_user.id).first()
        if existing:
            flash("Такое имя уже занято.", "error")
            return redirect(url_for("edit_profile"))

        if email:
            existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing_email:
                flash("Этот email уже используется.", "error")
                return redirect(url_for("edit_profile"))

        # 2) применяем изменения
        current_user.username = username
        current_user.email = email or None
        if password:
            current_user.set_password(password)

        # 3) ЗАГРУЗКА ФАЙЛА
        file = request.files.get("avatar_file")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Недопустимый формат. Разрешены: png, jpg, jpeg, gif, webp.", "error")
                return redirect(url_for("edit_profile"))

            fname = unique_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            file.save(save_path)

            # Опционально: удалить старый файл если он лежит в наших uploads
            old = (current_user.avatar_url or "")
            if old.startswith("/static/uploads/"):
                try:
                    old_path = os.path.join(app.root_path, old.lstrip('/'))
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except Exception:
                    pass  # молча, чтобы не ронять UX

            current_user.avatar_url = f"/static/uploads/{fname}"

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
    try:
        data = trending("movie", "week", 1)
        items = []
        for it in (data.get("results") or [])[:10]:
            items.append({
                "tmdb_id": it.get("id"),
                "title": it.get("title") or "Без названия",
                "poster": img_url(it.get("poster_path"), "w342"),
                "rating": it.get("vote_average"),
                "year": (it.get("release_date") or "")[:4],
            })
    except Exception as e:
        app.logger.error(f"Ошибка при загрузке трендов: {e}")
        items = []

    return render_template("index.html", items=items)


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
    # helper
    def parse_int(x, default=None):
        try: return int(x)
        except (TypeError, ValueError): return default

    if request.method == "POST":
        action = (request.form.get("action") or "").lower()

        # --- НОВОЕ: заметка по серии ---
        if media_type == "tv" and action in {"add_ep_note", "del_ep_note"}:
            if action == "add_ep_note":
                season = parse_int(request.form.get("ep_season"), 0) or 0
                episode = parse_int(request.form.get("ep_number"), 0) or 0
                text_note = (request.form.get("ep_note") or "").strip()

                if season <= 0 or episode <= 0:
                    flash("Укажи сезон и эпизод (положительные числа).", "error")
                    return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))
                if not text_note:
                    flash("Заметка не может быть пустой.", "error")
                    return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

                # upsert по уникальному ключу (user+tv+season+episode)
                note = EpisodeNote.query.filter_by(
                    user_id=current_user.id, tv_id=tmdb_id,
                    season=season, episode=episode
                ).first()
                if not note:
                    note = EpisodeNote(
                        user_id=current_user.id, tv_id=tmdb_id,
                        season=season, episode=episode, note=text_note
                    )
                    db.session.add(note)
                else:
                    note.note = text_note

                db.session.commit()
                flash(f"Заметка сохранена: S{season}E{episode}.", "success")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

            elif action == "del_ep_note":
                note_id = parse_int(request.form.get("note_id"))
                if note_id:
                    note = EpisodeNote.query.filter_by(id=note_id, user_id=current_user.id, tv_id=tmdb_id).first()
                    if note:
                        db.session.delete(note)
                        db.session.commit()
                        flash("Заметка удалена.", "success")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        # --- СТАРАЯ логика сохранения UserMedia (рейтинг/статус/прогресс и т.п.) ---
        # ... твой текущий код POST для рейтинга/статуса/сезонов/серий ...
        # В конце:
        # return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

    # --- GET ---
    info = details(media_type, tmdb_id)
    um = UserMedia.query.filter_by(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id).first()

    # НОВОЕ: подтянуть заметки по сериям текущего сериала
    episode_notes = []
    if media_type == "tv":
        rows = EpisodeNote.query.filter_by(user_id=current_user.id, tv_id=tmdb_id)\
                                .order_by(EpisodeNote.season.desc(), EpisodeNote.episode.desc())\
                                .all()
        episode_notes = [{
            "id": n.id, "season": n.season, "episode": n.episode,
            "note": n.note, "updated_at": n.updated_at
        } for n in rows]

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
        "user": um,
        "episode_notes": episode_notes,  # <— в шаблон
    }
    return render_template("title.html", **ctx)

@app.route("/my_list")
@login_required
def my_list():
    # Параметры (можно нажимать в UI): only=rated|all, sort=rating|-rating|added
    only = (request.args.get("only") or "rated").lower()
    sort = (request.args.get("sort") or "-rating").lower()
    mtype = (request.args.get("type") or "all").lower()  # all|movie|tv

    q = UserMedia.query.filter_by(user_id=current_user.id)

    # Фильтр по типу
    if mtype in {"movie", "tv"}:
        q = q.filter(UserMedia.media_type == mtype)

    # Только элементы с оценкой (по умолчанию)
    if only == "rated":
        q = q.filter(UserMedia.rating.isnot(None))

    # Сортировка
    if sort == "rating":
        q = q.order_by(UserMedia.rating.asc().nullslast())
    elif sort == "-rating":
        q = q.order_by(UserMedia.rating.desc().nullslast())
    else:  # added (по id как по дате добавления)
        q = q.order_by(UserMedia.id.desc())

    rows = q.all()

    # Собираем карточки для шаблона
    items = []
    for um in rows:
        try:
            info = details(um.media_type, um.tmdb_id)  # TMDB карточка
            items.append({
                "media_type": um.media_type,
                "tmdb_id": um.tmdb_id,
                "title": info.get("title") or info.get("name") or "Без названия",
                "year": (info.get("release_date") or info.get("first_air_date") or "")[:4],
                "poster": img_url(info.get("poster_path"), "w342"),
                "overview": info.get("overview"),
                "rating_user": um.rating,
                "status": um.status,
                "progress": um.progress,
                "href": url_for("title_page", media_type=um.media_type, tmdb_id=um.tmdb_id),
            })
        except Exception:
            # Если TMDB упал/отдал мусор — пропускаем элемент, но не валимся
            continue

    return render_template(
        "my_list.html",
        items=items,
        only=only,
        sort=sort,
        mtype=mtype
    )


@app.route("/stats")
@login_required
def stats():
    from sqlalchemy import func

    # Берём все юзерские записи
    q = UserMedia.query.filter_by(user_id=current_user.id)

    items_all = q.all()
    total = len(items_all)

    # Подсчёт по типам
    by_type = {"movie": 0, "tv": 0}
    for um in items_all:
        if um.media_type in by_type:
            by_type[um.media_type] += 1

    # Только с оценкой
    rated = [um for um in items_all if um.rating is not None]
    rated_count = len(rated)
    avg_rating = round(sum(um.rating for um in rated) / rated_count, 2) if rated_count else None

    # Распределение по статусам
    statuses = ["planned", "watching", "completed", "dropped"]
    status_counts = {s: 0 for s in statuses}
    for um in items_all:
        if um.status in status_counts:
            status_counts[um.status] += 1

    # Последние добавленные (по id как surrogate даты добавления)
    recent = sorted(items_all, key=lambda x: x.id, reverse=True)[:8]

    # Топ по оценке
    top_rated = sorted([um for um in items_all if um.rating is not None],
                       key=lambda x: (x.rating, x.id), reverse=True)[:8]

    # Собираем карточки для recent и top
    def hydrate(rows):
        out = []
        for um in rows:
            try:
                info = details(um.media_type, um.tmdb_id)
                out.append({
                    "media_type": um.media_type,
                    "tmdb_id": um.tmdb_id,
                    "title": info.get("title") or info.get("name") or "Без названия",
                    "year": (info.get("release_date") or info.get("first_air_date") or "")[:4],
                    "poster": img_url(info.get("poster_path"), "w342"),
                    "overview": info.get("overview"),
                    "rating_user": um.rating,
                    "href": url_for("title_page", media_type=um.media_type, tmdb_id=um.tmdb_id),
                })
            except Exception:
                continue
        return out

    ctx = {
        "total": total,
        "by_type": by_type,
        "rated_count": rated_count,
        "avg_rating": avg_rating,
        "status_counts": status_counts,
        "recent_items": hydrate(recent),
        "top_items": hydrate(top_rated),
    }
    return render_template("stats.html", **ctx)




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')