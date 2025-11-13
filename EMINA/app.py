from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

# --- Initialize Flask app ---
app = Flask(__name__)
app.secret_key = 'anime_emina'  # Change to secure random key in production

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
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


# --- Favorite Model ---
class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anime_title = db.Column(db.String(200), nullable=False)
    anime_image = db.Column(db.String(200), nullable=False)  # This now stores the full URL
    anime_url = db.Column(db.String(200), nullable=False)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)

    # Ensure a user cannot favorite the same anime twice
    __table_args__ = (db.UniqueConstraint('user_id', 'anime_title', name='_user_anime_uc'),)


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


# --- HELPER FUNCTION: Get Favorite Titles ---
def get_favorite_titles():
    """Fetches a list of favorited anime titles for the current user."""
    if 'user_id' in session:
        user_favorites = Favorite.query.filter_by(user_id=session['user_id']).all()
        return [fav.anime_title for fav in user_favorites]
    return []


# --- Public Routes (Unchanged) ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about.html')
def About():
    return render_template('About.html')


# --- Updated Content Routes to pass favorites (UPDATED) ---
@app.route('/most.html')
@login_required
def Most():
    favorite_titles = get_favorite_titles()
    return render_template('Most.html', favorite_titles=favorite_titles)


@app.route('/movie.html')
@login_required
def Movie():
    favorite_titles = get_favorite_titles()
    return render_template('Movie.html', favorite_titles=favorite_titles)


@app.route('/series.html')
@login_required
def Series():
    favorite_titles = get_favorite_titles()
    return render_template('Series.html', favorite_titles=favorite_titles)


# --- Authentication Routes (Unchanged) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")

        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="Email already registered!")

        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['user_name'] = new_user.name
        return redirect(url_for('Home'))

    return render_template('register.html')


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

        return render_template('login.html', error="Invalid email or password!")

    return render_template('login.html')


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('If an account exists for that email, a password reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- User Dashboard Routes (Home, Profile updated) ---
@app.route('/home')
@login_required
def Home():
    # Get user's favorite anime IDs for frontend checking
    favorite_titles = get_favorite_titles()
    return render_template('Home.html', name=session['user_name'], favorite_titles=favorite_titles)


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    # Fetch favorites with all details, ordered by date
    favorites = Favorite.query.filter_by(user_id=session['user_id']).order_by(Favorite.added_date.desc()).all()
    return render_template('profile.html', user=user, favorites=favorites)


@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    name = request.form['name']
    email = request.form['email']

    if User.query.filter(User.email == email, User.id != user.id).first():
        flash('Email already taken by another user!', 'error')
        return redirect(url_for('profile'))

    user.name = name
    user.email = email

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
    session.clear()
    flash('Your account has been deleted successfully.', 'success')
    return redirect(url_for('index'))


# --- Favorites Routes (UPDATED for robustness) ---
@app.route('/favorites/add', methods=['POST'])
@login_required
def add_favorite():
    data = request.get_json()
    anime_title = data.get('title')
    # This is now the static image FILENAME, e.g., 'attack.jpg'
    anime_image_filename = data.get('image')
    anime_url = data.get('url')

    if not anime_title or not anime_image_filename or not anime_url:
        return jsonify({'success': False, 'message': 'Missing anime data'}), 400

    # Check if already favorited
    existing = Favorite.query.filter_by(
        user_id=session['user_id'],
        anime_title=anime_title
    ).first()

    if existing:
        return jsonify({'success': False, 'message': 'Already in favorites'}), 400

    # --- FIX APPLIED HERE: CONSTRUCT THE CORRECT URL ---
    # Construct the full static URL using the filename provided by JS
    full_anime_image_url = url_for('static', filename=anime_image_filename)


    # Add to favorites
    new_favorite = Favorite(
        user_id=session['user_id'],
        anime_title=anime_title,
        # Store the correct, accessible URL
        anime_image=full_anime_image_url,
        anime_url=anime_url
    )
    db.session.add(new_favorite)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Added to favorites!'})


@app.route('/favorites/remove', methods=['POST'])
@login_required
def remove_favorite():
    data = request.get_json()
    anime_title = data.get('title')
    favorite_id = data.get('id')  # New check for removal by ID (for Profile page)

    favorite = None
    if favorite_id:
        # Removal from profile page by ID
        favorite = Favorite.query.filter_by(id=favorite_id, user_id=session['user_id']).first()
    elif anime_title:
        # Removal from content page by title
        favorite = Favorite.query.filter_by(user_id=session['user_id'], anime_title=anime_title).first()

    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Removed from favorites!'})

    return jsonify({'success': False, 'message': 'Not found in favorites'}), 404


@app.route('/favorites/check/<path:title>')
@login_required
def check_favorite(title):
    favorite = Favorite.query.filter_by(
        user_id=session['user_id'],
        anime_title=title
    ).first()
    return jsonify({'is_favorite': favorite is not None})


# --- Anime Content Routes (Login Required) (Unchanged) ---
ANIME_ROUTES = {
    'attack': 'Attack', 'attack2': 'Attack2',
    'naruto': 'Naruto', 'naruto2': 'Naruto2',
    'onepiece': 'OnePiece', 'onepiece2': 'OnePiece2',
    'metal': 'Metal', 'metal2': 'Metal2',
    'bleach': 'Bleach', 'bleach2': 'Bleach2',
    'broly': 'Broly', 'demon': 'Demon', 'demon2': 'Demon2',
    'mugen': 'Mugen', 'superhero': 'SuperHero'
}

# Dynamically create routes for all anime pages
for route_name, template_name in ANIME_ROUTES.items():
    app.add_url_rule(
        f'/{route_name}.html',
        endpoint=template_name,
        view_func=login_required(
            lambda t=template_name: render_template(f'{t}.html')
        )
    )

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)