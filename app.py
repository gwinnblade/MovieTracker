# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# === Настройки ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movietracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'diealready'  # !!! замени на случайную строку

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

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

# === Flask-Login ===
login_manager = LoginManager(app)
login_manager.login_view = "login"          # куда редиректить неавторизованных
login_manager.login_message = "Войдите, чтобы продолжить."

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

        # Валидация имени
        if not username:
            flash("Имя пользователя не может быть пустым.", "error")
            return redirect(url_for("edit_profile"))

        # Проверяем дубликаты
        existing = User.query.filter(User.username == username, User.id != current_user.id).first()
        if existing:
            flash("Такое имя уже занято.", "error")
            return redirect(url_for("edit_profile"))

        if email:
            existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing_email:
                flash("Этот email уже используется.", "error")
                return redirect(url_for("edit_profile"))

        # Обновляем данные
        current_user.username = username
        current_user.email = email if email else None
        if password:
            current_user.password_hash = generate_password_hash(password)

        db.session.commit()
        flash("Профиль успешно обновлён!", "success")
        return redirect(url_for("profile"))

    return render_template("edit_profile.html", user=current_user)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === Маршруты ===
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip() or None
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

@app.route("/catalog")
def catalog():
    return render_template('catalog.html')

@app.route("/my_list")
@login_required
def my_list():
    return render_template('my_list.html')

@app.route("/stats")
def stats():
    return render_template('stats.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
