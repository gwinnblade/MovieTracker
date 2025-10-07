from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movietracker.db'
db = SQLAlchemy(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html') #ОСНОВНАЯ СТРАНИЦА

@app.route("/catalog")
def catalog():
    return render_template('catalog.html')

@app.route("/my_list")
def my_list():
    return render_template('my_list.html')

@app.route("/stats")
def stats():
    return render_template('stats.html')

@app.route("/profile")
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
