from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Initialize Flask app ---
app = Flask(__name__)
app.secret_key = 'anime_emina'  # change this to something secure

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eminauser.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- User Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # If you implement token-based reset later, you would add fields here:
    # reset_token = db.Column(db.String(100), nullable=True)
    # reset_token_expiration = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """Hash password before saving"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password, password)


# --- Create tables ---
with app.app_context():
    db.create_all()


# --- Login Required Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first to view this content.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')


# ----------------- REGISTER -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error="Email already registered!")

        # Create new user
        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Log them in automatically
        session['user_id'] = new_user.id
        session['user_name'] = new_user.name
        return redirect(url_for('Home'))

    return render_template('register.html')


# ----------------- LOGIN -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            return redirect(url_for('Home'))
        else:
            return render_template('login.html', error="Invalid email or password!")

    return render_template('login.html')


# ----------------- FORGOT PASSWORD -----------------
# This route serves the forgot password form and handles the email submission.
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # NOTE: For a complete feature, you would generate a token, save it to the DB,
            # and use Flask-Mail to send an email with a reset link (e.g., url_for('reset_token', token=token)).
            # For now, we flash a success message assuming the email was sent.
            flash('If an account exists for that email, a password reset link has been sent.', 'success')
            return redirect(url_for('login'))
        else:
            # We still flash a generic success message for security reasons
            # (to avoid confirming which emails are registered).
            flash('If an account exists for that email, a password reset link has been sent.', 'success')
            return redirect(url_for('login'))

    # If GET request, display the form
    return render_template('forgot.html')


# ----------------- LOGOUT -----------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    return redirect(url_for('login'))


# ----------------- HOME -----------------
@app.route('/home')
@login_required
def Home():
    return render_template('Home.html', name=session['user_name'])


# ----------------- PROFILE -----------------
@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)


@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])

    name = request.form['name']
    email = request.form['email']

    # Check if email is already taken by another user
    existing_user = User.query.filter(User.email == email, User.id != user.id).first()
    if existing_user:
        flash('Email already taken by another user!', 'error')
        return redirect(url_for('profile'))

    user.name = name
    user.email = email

    # Update password if provided
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password:
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('profile'))
        user.set_password(new_password)

    db.session.commit()
    session['user_name'] = user.name
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))


@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    user = User.query.get(session['user_id'])
    db.session.delete(user)
    db.session.commit()

    session.pop('user_id', None)
    session.pop('user_name', None)

    flash('Your account has been deleted successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/about.html')
def About():
    return render_template('About.html')


@app.route('/most.html')
def Most():
    return render_template('Most.html')


@app.route('/movie.html')
def Movie():
    return render_template('Movie.html')


@app.route('/series.html')
def Series():
    return render_template('Series.html')


# --- PROTECTED ANIME PAGES (Login Required) ---
@app.route('/attack.html')
@login_required
def Attack():
    return render_template('Attack.html')


@app.route('/attack2.html')
@login_required
def Attack2():
    return render_template('Attack2.html')


@app.route('/naruto.html')
@login_required
def Naruto():
    return render_template('Naruto.html')


@app.route('/naruto2.html')
@login_required
def Naruto2():
    return render_template('Naruto2.html')


@app.route('/onepiece.html')
@login_required
def OnePiece():
    return render_template('OnePiece.html')


@app.route('/onepiece2.html')
@login_required
def OnePiece2():
    return render_template('OnePiece2.html')


@app.route('/metal.html')
@login_required
def Metal():
    return render_template('Metal.html')


@app.route('/metal2.html')
@login_required
def Metal2():
    return render_template('Metal2.html')


@app.route('/bleach.html')
@login_required
def Bleach():
    return render_template('Bleach.html')


@app.route('/bleach2.html')
@login_required
def Bleach2():
    return render_template('Bleach2.html')


@app.route('/broly.html')
@login_required
def Broly():
    return render_template('Broly.html')


@app.route('/demon.html')
@login_required
def Demon():
    return render_template('Demon.html')


@app.route('/demon2.html')
@login_required
def Demon2():
    return render_template('Demon2.html')


@app.route('/mugen.html')
@login_required
def Mugen():
    return render_template('Mugen.html')


@app.route('/superhero.html')
@login_required
def SuperHero():
    return render_template('SuperHero.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0',port=5000, debug=True)
