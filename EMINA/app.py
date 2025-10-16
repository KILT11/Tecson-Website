from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# --- Initialize Flask app ---
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # change this to something secure

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- User Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        """Hash password before saving"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password, password)

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


# ----------------- LOGOUT -----------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    return redirect(url_for('login'))


# ----------------- HOME -----------------
@app.route('/home')
def Home():
    if 'user_id' in session:
        return render_template('Home.html', name=session['user_name'])
    else:
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

@app.route('/attack.html')
def Attack():
    return render_template('Attack.html')

@app.route('/attack2.html')
def Attack2():
    return render_template('Attack2.html')

@app.route('/naruto.html')
def Naruto():
    return render_template('Naruto.html')

@app.route('/naruto2.html')
def Naruto2():
    return render_template('Naruto2.html')

@app.route('/onepiece.html')
def OnePiece():
    return render_template('OnePiece.html')

@app.route('/onepiece2.html')
def OnePiece2():
    return render_template('OnePiece2.html')

@app.route('/metal.html')
def Metal():
    return render_template('Metal.html')

@app.route('/metal2.html')
def Metal2():
    return render_template('Metal2.html')

@app.route('/bleach.html')
def Bleach():
    return render_template('Bleach.html')

@app.route('/bleach2.html')
def Bleach2():
    return render_template('Bleach2.html')

@app.route('/broly.html')
def Broly():
    return render_template('Broly.html')

@app.route('/demon.html')
def Demon():
    return render_template('Demon.html')

@app.route('/demon2.html')
def Demon2():
    return render_template('Demon2.html')

@app.route('/mugen.html')
def Mugen():
    return render_template('Mugen.html')

@app.route('/superhero.html')
def SuperHero():
    return render_template('SuperHero.html')




if __name__ == "__main__":
    app.run(debug=True)