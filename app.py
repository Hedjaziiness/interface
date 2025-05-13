from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from huggingface_hub import InferenceClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, LoginManager, current_user
from werkzeug.utils import secure_filename
import os
from flask import flash

from flask import make_response
from fpdf import FPDF

# Initialize the Flask app

app = Flask(__name__)


# Database setup

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = '20232025'

# Initialize database

db = SQLAlchemy(app)

# Initialize login manager

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup HuggingFace API

api_token = "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"
client = InferenceClient("HuggingFaceH4/zephyr-7b-beta", token=api_token)

def generate_text(prompt):
    return client.text_generation(prompt=prompt, max_new_tokens=200)

# Folder to save profile pictures

UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ========== MODELS ==========

class GeneratedText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(100))
    generated_text = db.Column(db.Text)

from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(20), nullable=False)  # Ensure role is NOT NULL

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== ROUTES ==========

from flask_login import login_required, current_user

@app.route("/")
@login_required
def index():
    texts = GeneratedText.query.all()  # Fetch all articles
    articles_count = len(texts)  # Count articles
    users_count = len(User.query.all())  # Count users

    # Admin can view users, regular users can't
    users = User.query.all() if current_user.role == 'admin' else []

    return render_template("index.html", texts=texts, users=users, articles_count=articles_count, users_count=users_count)

@app.route("/generate", methods=["POST"])
@login_required
def generate():
    topic = request.form["topic"]
    prompt = f"Rédige un article structuré sur le thème : {topic}"
    result = generate_text(prompt)

    new_text = GeneratedText(topic=topic, generated_text=result)
    db.session.add(new_text)
    db.session.commit()

    flash("✅ Article généré avec succès", "success")
    return redirect(url_for("index"))


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)  # Only admin can access this page
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route("/users")
@login_required
def user_management():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template("users.html", users=users)


@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        abort(403)  # Only admin can edit users
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

from flask_login import login_required, current_user

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user

    if request.method == "POST":
        user.username = request.form["username"]
        if 'image' in request.files:
            image = request.files['image']
            if image:
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                user.image = image_filename
        db.session.commit()
        return redirect(url_for('profile'))

    return render_template("profile.html", user=user)


@app.route("/articles")
@login_required
def articles():
    texts = GeneratedText.query.all()
    return render_template("articles.html", texts=texts)


@app.route("/edit_article/<int:text_id>", methods=["GET", "POST"])
@login_required
def edit_article(text_id):
    text = GeneratedText.query.get_or_404(text_id)

    if request.method == "POST":
        edited_text = request.form["edited_text"]
        text.generated_text = edited_text
        db.session.commit()
        return redirect(url_for('articles'))

    return render_template("edit_article.html", text=text)
from flask_login import login_required, current_user

@app.route("/send_to_admin/<int:text_id>", methods=["POST"])
@login_required
def send_to_admin(text_id):
    text = GeneratedText.query.get_or_404(text_id)
    print(f"Sent to admin: {text.generated_text}")
    return redirect(url_for('articles'))


@app.route("/admin/manage_users")
@login_required
def manage_users():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template("manage_users.html", users=users)


@app.route("/delete_article/<int:text_id>")
@login_required
def delete_article(text_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    article = GeneratedText.query.get_or_404(text_id)
    db.session.delete(article)
    db.session.commit()
    return redirect(url_for('index'))


@app.route("/delete_text/<int:id>")
@login_required
def delete_text(id):
    text = GeneratedText.query.get_or_404(id)
    db.session.delete(text)
    db.session.commit()
    flash("🗑️ Article supprimé", "info")
    return redirect(url_for("index"))


@app.route("/add_comment/<int:text_id>", methods=["POST"])
@login_required
def add_comment(text_id):
    user = current_user
    comment_content = request.form["comment"]
    comment = Comment(content=comment_content, user_id=user.id, article_id=text_id)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('articles'))


@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage_users'))


@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_text(id):
    text = GeneratedText.query.get_or_404(id)
    if request.method == "POST":
        text.generated_text = request.form["new_text"]
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("edit_text.html", text=text)


@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    username = request.form["username"]
    password = request.form["password"]
    role = request.form.get("role", "user")

    if username and password:
        hashed_pw = generate_password_hash(password)
        db.session.add(User(username=username, password=hashed_pw, role=role))
        db.session.commit()
    return redirect(url_for("index"))


@app.route("/send_text/<int:id>", methods=["GET", "POST"])
@login_required
def send_text(id):
    text = GeneratedText.query.get_or_404(id)
    users = User.query.all()
    if request.method == "POST":
        selected_users = request.form.getlist("users")
        for user_id in selected_users:
            user = User.query.get(int(user_id))
            print(f"Sending text to {user.username}: {text.generated_text}")
        return redirect(url_for("index"))
    return render_template("send_text.html", text=text, users=users)

from flask import render_template

@app.route("/export_pdf", methods=["POST"])
@login_required
def export_pdf():
    texts = GeneratedText.query.all()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Articles Générés", ln=True, align='C')
    pdf.ln(10)

    for text in texts:
        pdf.set_font("Arial", 'B', size=12)
        pdf.multi_cell(0, 10, f"🔹 Sujet: {text.topic}")
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 8, f"{text.generated_text}")
        pdf.ln(5)

    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=articles_dz.pdf'
    return response
@app.route("/validate_text/<int:id>")
@login_required
def validate_text(id):
    # Add your logic for validation here
    text = GeneratedText.query.get_or_404(id)
    # Process validation, e.g., mark as validated
    text.is_validated = True  # Assuming you have such a column in your model
    db.session.commit()
    flash("✅ Article validated successfully", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Hardcoded login for admin
        if username == "admin" and password == "admin123":
            session["user_id"] = 1  # Set a dummy user ID for the admin
            return redirect(url_for("index"))

        # Check for regular users in the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            return redirect(url_for("index"))
        else:
            return "Invalid username or password", 400

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))


# ========== INIT DB & ADMIN USER ==========

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
