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
from tmdb import trending, details, search, img_url, season_details
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

def ensure_owner(col: "Collection"):
    if not col or col.user_id != current_user.id:
        flash("Коллекция не найдена или у тебя нет прав.", "error")
        return False
    return True


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

class TvSeasonProgress(db.Model):
    __tablename__ = "tv_season_progress"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    tv_id = db.Column(db.Integer, nullable=False, index=True)     # TMDB id сериала
    season = db.Column(db.Integer, nullable=False)                # номер сезона
    watched = db.Column(db.Integer, default=0, nullable=False)    # сколько эпизодов из сезона просмотрено
    status = db.Column(db.String(20), nullable=True)              # planned/watching/completed/dropped
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "tv_id", "season", name="uq_user_tv_season"),
    )

class Collection(db.Model):
    __tablename__ = "collection"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cover_url = db.Column(db.String(255), nullable=True)   # обложка (опционально)
    is_public = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "title", name="uq_collection_user_title"),
    )


class CollectionItem(db.Model):
    __tablename__ = "collection_item"
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey("collection.id"), nullable=False, index=True)

    media_type = db.Column(db.String(10), nullable=False)  # "movie" | "tv"
    tmdb_id = db.Column(db.Integer, nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("collection_id", "media_type", "tmdb_id", name="uq_collection_item_unique"),
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

@app.route("/api/tv/<int:tmdb_id>/season/<int:season_number>")
@login_required
def api_tv_season(tmdb_id, season_number):
    """Вернёт точное количество эпизодов выбранного сезона."""
    try:
        data = season_details(tmdb_id, season_number)
        episodes = data.get("episodes", []) or []
        return {"ok": True, "episodes_count": len(episodes)}
    except Exception as e:
        app.logger.error(f"TMDb season_details error: tv={tmdb_id} s={season_number}: {e}")
        return {"ok": False, "episodes_count": None}, 500


@app.route("/api/tv/<int:tmdb_id>/season/<int:season_number>/progress")
@login_required
def api_tv_season_progress(tmdb_id, season_number):
    """Вернёт сохранённый прогресс в сезоне (сколько серий посмотрел) и статус сезона для текущего пользователя."""
    row = TvSeasonProgress.query.filter_by(
        user_id=current_user.id, tv_id=tmdb_id, season=season_number
    ).first()
    return {
        "ok": True,
        "watched": (row.watched if row else 0),
        "status": (row.status if row and row.status else None),
    }




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
    def _i(x, d=None):
        try: return int(x)
        except (TypeError, ValueError): return d

    # --- POST действий три: общая заметка; заметка по серии; удаление заметки серии
    if request.method == "POST":
        action = (request.form.get("action") or "").lower()

        # 1) Общая заметка по фильму/сериалу (не эпизод)
        if action == "save_title_note":
            text = (request.form.get("title_note") or "").strip()
            um = UserMedia.query.filter_by(
                user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id).first()
            if not um:
                um = UserMedia(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id)
                db.session.add(um)
            um.note = text or None
            db.session.commit()
            flash("Заметка сохранена.", "success")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        if action == "save_status":
            raw = (request.form.get("status") or "").strip().lower()
            allowed = {"planned", "watching", "completed", "dropped"}
            if raw not in allowed:
                flash("Некорректный статус.", "error")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

            um = UserMedia.query.filter_by(
                user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id
            ).first()
            if not um:
                um = UserMedia(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id)
                db.session.add(um)

            um.status = raw
            db.session.commit()
            flash("Статус обновлён.", "success")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        if action == "save_rating":
            rating = _i(request.form.get("rating"), None)
            if rating is None or not (1 <= rating <= 10):
                flash("Оценка должна быть от 1 до 10.", "error")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

            um = UserMedia.query.filter_by(
                user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id
            ).first()
            if not um:
                um = UserMedia(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id)
                db.session.add(um)

            um.rating = rating
            db.session.commit()
            flash("Оценка сохранена.", "success")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

        # 1.2) Прогресс по сезону (только для сериалов)
        if action == "save_season_progress" and media_type == "tv":
            season = _i(request.form.get("season"), 0) or 0
            watched = _i(request.form.get("season_watched"), 0) or 0
            season_status = (request.form.get("season_status") or "").strip().lower() or None

            allowed_status = {"planned", "watching", "completed", "dropped", None}
            if season_status not in allowed_status:
                season_status = None

            if season <= 0:
                flash("Неверный номер сезона.", "error")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

            # Узнаём точное число серий в сезоне, чтобы ограничить watched
            try:
                season_data = season_details(tmdb_id, season)
                max_eps = len(season_data.get("episodes", []) or [])
            except Exception:
                max_eps = None

            watched = max(0, watched)
            if max_eps is not None:
                watched = min(watched, max_eps)

            row = TvSeasonProgress.query.filter_by(
                user_id=current_user.id, tv_id=tmdb_id, season=season
            ).first()
            if not row:
                row = TvSeasonProgress(
                    user_id=current_user.id, tv_id=tmdb_id, season=season,
                    watched=watched, status=season_status
                )
                db.session.add(row)
            else:
                row.watched = watched
                row.status = season_status

            # Синхронизируем общий UserMedia + суммарное количество просмотренных серий по всему сериалу
            um = UserMedia.query.filter_by(
                user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id
            ).first()
            if not um:
                um = UserMedia(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id)
                db.session.add(um)
            if season_status:
                um.status = season_status

            total_watched = db.session.query(db.func.coalesce(db.func.sum(TvSeasonProgress.watched), 0)) \
                                      .filter_by(user_id=current_user.id, tv_id=tmdb_id).scalar()
            um.episodes_watched = int(total_watched or 0)

            db.session.commit()
            flash("Прогресс по сезону сохранён.", "success")
            return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))


        # 2) Заметки по сериям (только для сериалов)
        if media_type == "tv" and action in {"add_ep_note", "del_ep_note"}:
            if action == "add_ep_note":
                season = _i(request.form.get("ep_season"), 0) or 0
                episode = _i(request.form.get("ep_number"), 0) or 0
                text = (request.form.get("ep_note") or "").strip()
                if season <= 0 or episode <= 0:
                    flash("Укажи сезон и эпизод (>0).", "error")
                    return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))
                if not text:
                    flash("Заметка не может быть пустой.", "error")
                    return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

                note = EpisodeNote.query.filter_by(
                    user_id=current_user.id, tv_id=tmdb_id, season=season, episode=episode
                ).first()
                if not note:
                    note = EpisodeNote(
                        user_id=current_user.id, tv_id=tmdb_id,
                        season=season, episode=episode, note=text
                    )
                    db.session.add(note)
                else:
                    note.note = text
                db.session.commit()
                flash(f"Заметка S{season}E{episode} сохранена.", "success")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

            if action == "del_ep_note":
                note_id = _i(request.form.get("note_id"))
                if note_id:
                    n = EpisodeNote.query.filter_by(id=note_id, user_id=current_user.id, tv_id=tmdb_id).first()
                    if n:
                        db.session.delete(n)
                        db.session.commit()
                        flash("Заметка удалена.", "success")
                return redirect(url_for("title_page", media_type=media_type, tmdb_id=tmdb_id))

    # --- GET: собираем карточку, сезоны, заметки
    info = details(media_type, tmdb_id)
    um = UserMedia.query.filter_by(user_id=current_user.id, media_type=media_type, tmdb_id=tmdb_id).first()

    # Коллекции пользователя для выпадающего списка «Добавить в коллекцию»
    user_cols = []
    if current_user.is_authenticated:
        user_cols = Collection.query.filter_by(user_id=current_user.id).order_by(Collection.id.desc()).all()


    # Общая заметка для фильма/сериала — это um.note
    title_note = (um.note if um and um.note else "")

    # Список заметок по сериям (для TV)
    episode_notes = []
    season_options, season_selected, episodes_list, episodes_count_exact = [], None, [], None

    if media_type == "tv":
        # Предзаполняем форму прогресса по выбранному сезону
        season_progress_watched = 0
        season_progress_status = None
        if season_selected:
            row = TvSeasonProgress.query.filter_by(
                user_id=current_user.id, tv_id=tmdb_id, season=season_selected
            ).first()
            if row:
                season_progress_watched = row.watched or 0
                season_progress_status = row.status


        seasons_meta = info.get("seasons") or []
        q_season = request.args.get("season")
        season_selected = _i(q_season, None)

        if not season_selected:
            nums = [s.get("season_number", 0) for s in seasons_meta]
            if 1 in nums:
                season_selected = 1
            else:
                season_selected = min([n for n in nums if n > 0], default=(nums[0] if nums else 1))

        cache_key = f"tv:{tmdb_id}:season:{season_selected}"
        season_data = cache.get(cache_key)
        if season_data is None:
            try:
                season_data = season_details(tmdb_id, season_selected)
            except Exception as e:
                app.logger.error(f"TMDb season_details error: tv={tmdb_id} s={season_selected}: {e}")
                season_data = {"episodes": []}
            cache.set(cache_key, season_data, timeout=300)

        episodes_list = season_data.get("episodes", []) or []
        episodes_count_exact = len(episodes_list)

        season_options = [{
            "num": s.get("season_number"),
            "label": (s.get("name") or f"Сезон {s.get('season_number')}").strip(),
            "episode_count": s.get("episode_count")
        } for s in seasons_meta if s.get("season_number") is not None]

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
        "season_progress_watched": season_progress_watched if media_type == "tv" else None,
        "season_progress_status": season_progress_status if media_type == "tv" else None,
        "collections": user_cols,

        # Пользовательские данные
        "user_status": (um.status if um else None),
        "user_rating": (um.rating if um else None),

        # Заметки
        "title_note": title_note,
        "episode_notes": episode_notes,

        # Сезоны
        "season_options": season_options,
        "season_selected": season_selected,
        "episodes_count_exact": episodes_count_exact,
        "episodes_list": episodes_list,
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

@app.route("/collections", methods=["GET", "POST"])
@login_required
def collections():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip() or None
        is_public = bool(request.form.get("is_public"))

        if not title:
            flash("Название коллекции не может быть пустым.", "error")
            return redirect(url_for("collections"))

        # проверка уникальности названия в рамках пользователя
        exists = Collection.query.filter_by(user_id=current_user.id, title=title).first()
        if exists:
            flash("У тебя уже есть коллекция с таким названием.", "error")
            return redirect(url_for("collections"))

        col = Collection(user_id=current_user.id, title=title, description=description, is_public=is_public)
        db.session.add(col)
        db.session.commit()
        flash("Коллекция создана!", "success")
        return redirect(url_for("collection_view", cid=col.id))

    rows = Collection.query.filter_by(user_id=current_user.id).order_by(Collection.id.desc()).all()
    return render_template("collections.html", rows=rows)

@app.route("/collections/<int:cid>")
@login_required
def collection_view(cid):
    col = db.session.get(Collection, cid)
    if not col:
        flash("Коллекция не найдена.", "error")
        return redirect(url_for("collections"))

    # приватные коллекции видны только владельцу
    if not col.is_public and col.user_id != current_user.id:
        flash("Эта коллекция приватная.", "error")
        return redirect(url_for("collections"))

    # грузим элементы и гидратируем карточки через TMDb
    items_q = CollectionItem.query.filter_by(collection_id=cid).order_by(CollectionItem.id.desc()).all()
    items = []
    for it in items_q:
        try:
            info = details(it.media_type, it.tmdb_id)
            items.append({
                "media_type": it.media_type,
                "tmdb_id": it.tmdb_id,
                "title": info.get("title") or info.get("name") or "Без названия",
                "year": (info.get("release_date") or info.get("first_air_date") or "")[:4],
                "poster": img_url(info.get("poster_path"), "w342"),
                "href": url_for("title_page", media_type=it.media_type, tmdb_id=it.tmdb_id),
            })
        except Exception:
            continue

    is_owner = (col.user_id == current_user.id)
    return render_template("collection_view.html", col=col, items=items, is_owner=is_owner)

@app.route("/collections/<int:cid>/add", methods=["POST"])
@login_required
def collection_add_item(cid):
    col = db.session.get(Collection, cid)
    if not ensure_owner(col):
        return redirect(url_for("collections"))

    media_type = (request.form.get("media_type") or "").lower()
    tmdb_id = parse_int(request.form.get("tmdb_id"))

    if media_type not in {"movie", "tv"} or not tmdb_id:
        flash("Неверные данные.", "error")
        return redirect(url_for("collection_view", cid=cid))

    # upsert-защита по уникальному индексу
    exists = CollectionItem.query.filter_by(collection_id=cid, media_type=media_type, tmdb_id=tmdb_id).first()
    if exists:
        flash("Уже в коллекции.", "info")
    else:
        db.session.add(CollectionItem(collection_id=cid, media_type=media_type, tmdb_id=tmdb_id))
        db.session.commit()
        flash("Добавлено в коллекцию.", "success")

    return redirect(url_for("collection_view", cid=cid))


@app.route("/collections/<int:cid>/remove", methods=["POST"])
@login_required
def collection_remove_item(cid):
    col = db.session.get(Collection, cid)
    if not ensure_owner(col):
        return redirect(url_for("collections"))

    media_type = (request.form.get("media_type") or "").lower()
    tmdb_id = parse_int(request.form.get("tmdb_id"))
    row = CollectionItem.query.filter_by(collection_id=cid, media_type=media_type, tmdb_id=tmdb_id).first()
    if row:
        db.session.delete(row)
        db.session.commit()
        flash("Удалено из коллекции.", "success")
    else:
        flash("Элемента нет в коллекции.", "error")
    return redirect(url_for("collection_view", cid=cid))
@app.route("/collections/<int:cid>/edit", methods=["POST"])
@login_required
def collection_edit(cid):
    col = db.session.get(Collection, cid)
    if not ensure_owner(col):
        return redirect(url_for("collections"))

    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    is_public = bool(request.form.get("is_public"))

    if not title:
        flash("Название не может быть пустым.", "error")
        return redirect(url_for("collection_view", cid=cid))

    # проверка уникальности названия, кроме текущей коллекции
    dup = Collection.query.filter(Collection.user_id == current_user.id, Collection.title == title, Collection.id != cid).first()
    if dup:
        flash("Другая твоя коллекция уже носит это имя.", "error")
        return redirect(url_for("collection_view", cid=cid))

    col.title = title
    col.description = description
    col.is_public = is_public
    db.session.commit()
    flash("Коллекция обновлена.", "success")
    return redirect(url_for("collection_view", cid=cid))


@app.route("/collections/<int:cid>/delete", methods=["POST"])
@login_required
def collection_delete(cid):
    col = db.session.get(Collection, cid)
    if not ensure_owner(col):
        return redirect(url_for("collections"))
    # каскадно удалим элементы
    CollectionItem.query.filter_by(collection_id=cid).delete()
    db.session.delete(col)
    db.session.commit()
    flash("Коллекция удалена.", "success")
    return redirect(url_for("collections"))






if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
