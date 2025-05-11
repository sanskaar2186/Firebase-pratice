from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, firestore, exceptions
import os
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'your-secret-key-here'

# Initialize Firebase Admin SDK
cred = credentials.Certificate('firebase-config.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# Helper Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_data(uid):
    user_ref = db.collection('users').document(uid)
    doc = user_ref.get()
    return doc.to_dict() if doc.exists else None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        id_token = request.form.get('idToken')
        
        if not id_token:
            flash('Invalid authentication request', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Verify ID token
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            
            # Get Firebase user record
            firebase_user = auth.get_user(uid)
            
            # Create session
            session['user'] = {
                'uid': uid,
                'email': firebase_user.email,
                'email_verified': firebase_user.email_verified,
                'last_login': datetime.now().isoformat()
            }
            
            # Update or create user in Firestore
            user_ref = db.collection('users').document(uid)
            if not user_ref.get().exists:
                user_ref.set({
                    'email': firebase_user.email,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'last_login': firestore.SERVER_TIMESTAMP,
                    'provider': firebase_user.provider_data[0].provider_id if firebase_user.provider_data else 'password'
                })
            else:
                user_ref.update({
                    'last_login': firestore.SERVER_TIMESTAMP
                })
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except exceptions.FirebaseError as e:
            flash(f'Login failed: {str(e)}', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        id_token = request.form.get('idToken')
        
        try:
            if id_token:
                # Handle social registration (Google, etc.)
                decoded_token = auth.verify_id_token(id_token)
                uid = decoded_token['uid']
                firebase_user = auth.get_user(uid)
            else:
                # Handle email/password registration
                if not email or not password:
                    flash('Email and password are required', 'danger')
                    return redirect(url_for('register'))
                
                # Create Firebase user
                firebase_user = auth.create_user(
                    email=email,
                    password=password
                )
                uid = firebase_user.uid
            
            # Create user in Firestore
            user_data = {
                'email': firebase_user.email,
                'created_at': firestore.SERVER_TIMESTAMP,
                'last_login': firestore.SERVER_TIMESTAMP,
                'provider': firebase_user.provider_data[0].provider_id if firebase_user.provider_data else 'password'
            }
            
            db.collection('users').document(uid).set(user_data)
            
            # Create session
            session['user'] = {
                'uid': uid,
                'email': firebase_user.email,
                'email_verified': firebase_user.email_verified,
                'last_login': datetime.now().isoformat()
            }
            
            flash('Registration successful!', 'success')
            return redirect(url_for('dashboard'))
            
        except exceptions.FirebaseError as e:
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get additional user data from Firestore
        user_data = get_user_data(session['user']['uid'])
        
        if not user_data:
            flash('User data not found', 'warning')
            return redirect(url_for('logout'))
        
        return render_template('dashboard.html', 
                            user=session['user'],
                            user_data=user_data)
    
    except exceptions.FirebaseError as e:
        flash(f'Session error: {str(e)}', 'danger')
        return redirect(url_for('logout'))

@app.route('/logout')
def logout():
    # Clear Flask session
    session.pop('user', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# API Endpoints
@app.route('/api/verify-token', methods=['POST'])
def api_verify_token():
    try:
        data = request.get_json()
        if not data or 'token' not in data:
            print("No token provided in request")
            return jsonify({
                'success': False,
                'error': 'No token provided'
            }), 400

        id_token = data['token']
        print(f"Verifying token: {id_token[:20]}...")
        
        decoded_token = auth.verify_id_token(id_token)
        print(f"Token verified successfully for user: {decoded_token['uid']}")
        
        # Create or update user in Firestore
        user_ref = db.collection('users').document(decoded_token['uid'])
        user_data = {
            'email': decoded_token.get('email'),
            'last_login': firestore.SERVER_TIMESTAMP,
            'email_verified': decoded_token.get('email_verified', False)
        }
        
        if not user_ref.get().exists:
            user_data['created_at'] = firestore.SERVER_TIMESTAMP
            user_ref.set(user_data)
            print(f"Created new user document for {decoded_token['uid']}")
        else:
            user_ref.update(user_data)
            print(f"Updated existing user document for {decoded_token['uid']}")
        
        # Create session
        session['user'] = {
            'uid': decoded_token['uid'],
            'email': decoded_token.get('email'),
            'email_verified': decoded_token.get('email_verified', False),
            'last_login': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'uid': decoded_token['uid']
        }), 200
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 401

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)