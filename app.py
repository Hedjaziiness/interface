from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from huggingface_hub import InferenceClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import IntegerField, TextAreaField
from wtforms.validators import InputRequired, NumberRange
from fpdf import FPDF
import os

# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = '20232025'  # Consider using a stronger secret key in production

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup HuggingFace API
api_token = "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"
client = InferenceClient("inessiness/gpt2-fr-articles", token=api_token)

def generate_text(prompt):
    return client.text_generation(prompt=prompt, max_new_tokens=200)

# Folder for profile pictures
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ========== MODELS ==========

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'
    image = db.Column(db.String(150), nullable=True)  # Profile picture filename

class GeneratedText(db.Model):
    __tablename__ = 'generated_text'
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(100), nullable=False)
    generated_text = db.Column(db.Text, nullable=False)
    style_rating = db.Column(db.Integer, nullable=True)
    criteria_rating = db.Column(db.Integer, nullable=True)
    comment = db.Column(db.Text, nullable=True)
    is_validated = db.Column(db.Boolean, default=False)  # For validation status

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey('generated_text.id'), nullable=False)
    style_rating = db.Column(db.Integer)
    criteria_rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    article = db.relationship('GeneratedText', backref=db.backref('evaluations', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('generated_text.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    article = db.relationship('GeneratedText', backref='comments')

class RatingForm(FlaskForm):
    style = IntegerField('Style', validators=[InputRequired(), NumberRange(min=1, max=5)])
    criteria = IntegerField('Criteria', validators=[InputRequired(), NumberRange(min=1, max=5)])
    comment = TextAreaField('Commentaire', validators=[InputRequired()])

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== ROUTES ==========

@app.route("/")
@login_required
def index():
    texts = GeneratedText.query.all()
    users = User.query.all() if current_user.role == 'admin' else []
    return render_template("index.html", texts=texts, users=users)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("✅ Login successful", "success")
            return redirect(url_for("index"))
        else:
            flash("❌ Invalid username or password", "error")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    from flask_login import logout_user
    logout_user()
    flash("✅ Logged out successfully", "success")
    return redirect(url_for("login"))

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

@app.route("/articles")
@login_required
def articles():
    texts = GeneratedText.query.all()
    return render_template("articles.html", texts=texts)

@app.route('/article/<int:article_id>')
@login_required
def article_detail(article_id):
    article = GeneratedText.query.get_or_404(article_id)
    evaluations = Evaluation.query.filter_by(article_id=article_id).all()
    return render_template('article.html', article=article, evaluations=evaluations)

@app.route("/rate/<int:id>", methods=["GET", "POST"])
@login_required
def rate_article(id):
    article = GeneratedText.query.get_or_404(id)
    form = RatingForm()
    if form.validate_on_submit():
        article.style_rating = form.style.data
        article.criteria_rating = form.criteria.data
        article.comment = form.comment.data
        db.session.commit()
        flash("✅ Article évalué avec succès", "success")
        return redirect(url_for('index'))
    return render_template("rate_article.html", form=form, article=article)

@app.route("/edit_article/<int:text_id>", methods=["GET", "POST"])
@login_required
def edit_article(text_id):
    text = GeneratedText.query.get_or_404(text_id)
    if request.method == "POST":
        text.generated_text = request.form["edited_text"]
        db.session.commit()
        flash("✅ Article modifié avec succès", "success")
        return redirect(url_for('articles'))
    return render_template("edit_article.html", text=text)

@app.route("/send_to_admin/<int:text_id>", methods=["POST"])
@login_required
def send_to_admin(text_id):
    text = GeneratedText.query.get_or_404(text_id)
    print(f"Sent to admin: {text.generated_text}")  # Replace with actual notification logic
    flash("✅ Article envoyé à l'admin", "success")
    return redirect(url_for('articles'))

@app.route("/delete_article/<int:text_id>")
@login_required
def delete_article(text_id):
    if current_user.role != 'admin':
        abort(403)
    article = GeneratedText.query.get_or_404(text_id)
    db.session.delete(article)
    db.session.commit()
    flash("🗑️ Article supprimé", "info")
    return redirect(url_for('index'))

@app.route("/add_comment/<int:text_id>", methods=["POST"])
@login_required
def add_comment(text_id):
    comment_content = request.form["comment"]
    comment = Comment(content=comment_content, user_id=current_user.id, article_id=text_id)
    db.session.add(comment)
    db.session.commit()
    flash("✅ Commentaire ajouté", "success")
    return redirect(url_for('articles'))

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()
        flash("✅ Utilisateur modifié", "success")
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("🗑️ Utilisateur supprimé", "info")
    return redirect(url_for('admin_users'))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.username = request.form["username"]
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename:
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                current_user.image = image_filename
        db.session.commit()
        flash("✅ Profil mis à jour", "success")
        return redirect(url_for('profile'))
    return render_template("profile.html", user=current_user)

@app.route("/send_text/<int:id>", methods=["GET", "POST"])
@login_required
def send_text(id):
    text = GeneratedText.query.get_or_404(id)
    users = User.query.all()
    if request.method == "POST":
        selected_users = request.form.getlist("users")
        for user_id in selected_users:
            user = User.query.get(int(user_id))
            print(f"Sending text to {user.username}: {text.generated_text}")  # Replace with actual notification
        flash("✅ Texte envoyé aux utilisateurs sélectionnés", "success")
        return redirect(url_for("index"))
    return render_template("send_text.html", text=text, users=users)

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
    if current_user.role != 'admin':
        abort(403)
    text = GeneratedText.query.get_or_404(id)
    text.is_validated = True
    db.session.commit()
    flash("✅ Article validé avec succès", "success")
    return redirect(url_for("index"))

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
