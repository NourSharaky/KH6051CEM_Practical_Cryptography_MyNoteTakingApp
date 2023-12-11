# Flask and related functionalities
from flask import Flask, render_template, request, redirect, url_for , make_response  , jsonify
# SQLAlchemy for database interaction
from flask_sqlalchemy import SQLAlchemy
# JWT for token-based authentication
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity , verify_jwt_in_request
# Password hashing and verification
from werkzeug.security import generate_password_hash, check_password_hash
# Decorator functionality
from functools import wraps
# Exception handling for database errors
from sqlalchemy.exc import IntegrityError
# Form creation and validation
from flask_wtf import FlaskForm
from wtforms import TextAreaField , HiddenField
# Encryption and decryption using AES
from AES import AESCipher
# System-related functions and libraries
import os
from base64 import b64encode, b64decode

# -----------------------------------------------------------------

# Create a Flask application instance
app = Flask(__name__)

# Configure SQLAlchemy database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myDatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Generate a secret key for JWT tokens
JWTSECRET = os.urandom(32)
app.config['JWT_SECRET_KEY'] = JWTSECRET  

# Generate a random secret key for CSRF protection
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize Flask extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Create an AES encryption engine with a pre-defined key
AESKEY = "6a9937dd13896bdb9ab0e6e9e880ede071e19ea3f20a16e4e43069a86451779b"
cipherEngine = AESCipher(AESKEY)

#-----------------------------------------------------------------
# Models

# User model with attributes and relationships
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(160), unique=True, nullable=False)
    password = db.Column(db.String(240), nullable=False)
    notes = db.relationship('Note', backref='user', lazy=True)

# Note model with attributes and foreign key relationship to User
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False, default='New Note')
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# -----------------------------------------------------------------

# Create database tables if not already exist
with app.app_context():
    db.create_all()

#-----------------------------------------------------------------

# Decorator to protect routes requiring authentication
def Protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Retrieve the access token from the cookie
        access_token_cookie = request.cookies.get('access_token_cookie')

        # Redirect to login if no access token found
        if not access_token_cookie:
            return redirect(url_for('logout'))
            
        # Verify the access token
        try:
            verify_jwt_in_request(locations=['cookies'])
        except Exception as e:
            return redirect(url_for('logout'))
            
        # Pass request to the decorated function
        return fn(*args, **kwargs)

    return wrapper

#-----------------------------------------------------------------
#region Login Routes

# Home page route accessible only after successful login
@app.route('/')
@app.route('/<noteID>')
@Protected
def index(noteID : int =-1):
    # Try to retrieve logged-in user
    try:
        current_user = get_jwt_identity()
    except:
        current_user = None

    # Redirect to login if no user is logged in
    if not current_user:
        return redirect(url_for('login'))
    
    # Encode username for database query
    current_user_enc = b64encode(current_user.encode('utf-8')).decode("ascii")
    # Retrieve user object from database
    userDB = User.query.filter_by(username=current_user_enc).first()
    # Initialize note variable
    note = None
    
    # Try to retrieve specific note if note ID is provided
    try:
        if int(noteID) > -1 and int(noteID) <= len(userDB.notes):
            note = userDB.notes[int(noteID)-1]
        
        # Render index page with user, notes, and note form
        if current_user:
            return render_template('index.html', user=current_user , notes=userDB.notes , form=NoteForm() , note=note , cipherEngine=cipherEngine)
        else:
            # Redirect to login page if user is not logged in
            redirect(url_for('login'))

    except ValueError:
        # Redirect to index page if invalid note ID is provided
        return redirect(url_for('index'))

# -----------------------------------------------------------------

# Login page for user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Process login form submission
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Encode username for database query
        username_enc = b64encode(username.encode('utf-8')).decode("ascii") 
        # Retrieve user from database
        user = User.query.filter_by(username=username_enc).first()

        # Verify password and generate access token if valid
        if user and check_password_hash(cipherEngine.decrypt(user.password), password):
            username_dec = b64decode(user.username).decode("utf-8")
            access_token = create_access_token(identity=username_dec)

            # Set the access token in a cookie
            response = make_response(redirect(url_for('index')))
            response.set_cookie('access_token_cookie', access_token)

            return response
        
        # Render login page with error message if login fails
        else:
            return render_template("login.html", msg='Login Failed. Invalid username or password.')
    # Render login page
    return render_template('login.html')

# -----------------------------------------------------------------

# Signup page for user registration
@app.route('/signup', methods=['POST',"GET"])
def signup():
    # Process signup form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate form inputs
        if not username or not password or not confirm_password:
            return render_template('signup.html' , msg="Please fill out all fields")

        # Check if passwords match
        if password != confirm_password:
            return  render_template('signup.html' , msg='Passwords do not match')

        # Hash and encrypt password for secure storage
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        password_enc = cipherEngine.encrypt(hashed_password)

        # Encode username for database storage
        username_enc = b64encode(username.encode('utf-8')).decode("ascii")

        # Create and save new user to database
        new_user = User(username=username_enc , password=password_enc)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login after successful signup
        response = make_response(redirect(url_for('login')))
        response.headers['Location'] = url_for('login')

        # response.set_cookie('access_token_cookie', create_access_token(identity=username))
        return response
    # Render signup page
    return render_template('signup.html')

# -----------------------------------------------------------------

# Logout route to clear access token and redirect to login
@app.route('/logout', methods=['GET'])
def logout():
    # Clear the access token cookie
    response = make_response(redirect(url_for("login")))
    response.delete_cookie('access_token_cookie')
    return response

#endregion

#-----------------------------------------------------------------
#region Notes Routes

# Define form class for adding and editing notes
class NoteForm(FlaskForm):
    id = HiddenField('Note ID')
    title = TextAreaField('Note Title')
    content = TextAreaField('Note Content')

# -----------------------------------------------------------------

# Route for adding or updating notes
@app.route('/notes', methods=['POST'])
@Protected
def add_note():
    # Get currently logged-in user
    current_user = get_jwt_identity()
    current_user_enc = b64encode(current_user.encode('utf-8')).decode("ascii")
    user = User.query.filter_by(username=current_user_enc).first()

    # Process note form submission
    if request.method == 'POST':
        form = NoteForm(request.form)
        # Validate form data
        if form.validate():
            # Check if note is for update or creation
            if(form.id.data != ""):
                form_data = dict(request.form)
                mynote = Note.query.filter_by(id=form_data["note_id"], user=user).first()
            else:
                print("no ID")
                mynote = None

            # Update existing note
            if mynote:
                print("update")
                mynote.title = cipherEngine.encrypt(form.title.data)
                mynote.content = cipherEngine.encrypt(form.content.data)
                db.session.commit()
                thenoteid = mynote.id

            # Create new note
            else:
                print("new")
                new_note = Note(title=cipherEngine.encrypt(form.title.data) ,content=cipherEngine.encrypt(form.content.data), user=user)
                db.session.add(new_note)
                db.session.commit()
                thenoteid = new_note.id

            # Redirect to index page with updated note ID
            return redirect(url_for('index', noteID=thenoteid))
    # Redirect to index page if form validation fails
    return redirect(url_for('index'))

# -----------------------------------------------------------------

# Route for deleting notes
@app.route('/notes/<int:note_id>/delete', methods=['GET'])
@Protected
def delete_note(note_id):
    # Retrieve the note with the provided ID
    note = Note.query.get(note_id)

    # Check if the note exists
    if note:
        # Delete the note and commit the change to the database
        db.session.delete(note)
        db.session.commit()

        # Create a response object for redirection
        response = make_response(redirect(url_for("index")))
    else:
        # Create a response object for redirection in case of non-existent note
        response = make_response(redirect(url_for("index")))

    # Return the response object
    return response

#endregion
#-----------------------------------------------------------------

if __name__ == '__main__':
    # Run the Flask application in debug mode on port 443 using the provided SSL certificates
    app.run(debug=True , ssl_context=('SSL/cert.pem', 'SSL/key.pem') , port=443) 