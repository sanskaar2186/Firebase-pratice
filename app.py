from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
import firebase_admin
from firebase_admin import credentials, auth, firestore, exceptions, storage
import os
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'your-secret-key-here'

# Initialize Firebase Admin SDK
cred = credentials.Certificate('firebase-config.json')
firebase_admin.initialize_app(cred, {
    'storageBucket': 'fir-pra-bec88.firebasestorage.app'
})

# Initialize Firestore and Storage
db = firestore.client()
bucket = storage.bucket()

# Configure CORS for the bucket
cors_configuration = {
    'origin': ['*'],
    'method': ['GET', 'POST', 'PUT', 'DELETE'],
    'responseHeader': ['Content-Type', 'Access-Control-Allow-Origin'],
    'maxAgeSeconds': 3600
}
bucket.cors = [cors_configuration]
bucket.update()

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
    try:
        user_ref = db.collection('users').document(uid)
        doc = user_ref.get()
        if doc.exists:
            return doc.to_dict()
        return None
    except Exception as e:
        print(f"Error fetching user data: {str(e)}")
        return None

def update_user_session(user_data):
    session['user'] = {
        'uid': user_data.get('uid'),
        'email': user_data.get('email'),
        'name': user_data.get('name'),
        'photo_url': user_data.get('photo_url'),
        'email_verified': user_data.get('email_verified', False),
        'last_login': datetime.now().isoformat()
    }

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

@app.route('/profile')
@login_required
def profile():
    try:
        user_data = get_user_data(session['user']['uid'])
        if not user_data:
            flash('User data not found', 'warning')
            return redirect(url_for('dashboard'))
        
        return render_template('profile.html', 
                            user=session['user'],
                            user_data=user_data)
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        user_ref = db.collection('users').document(session['user']['uid'])
        updates = {
            'name': request.form.get('name'),
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                try:
                    print(f"Processing file: {file.filename}")  # Debug log
                    
                    # Validate file type
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                    print(f"File extension: {file_ext}")  # Debug log
                    
                    if file_ext not in allowed_extensions:
                        flash('Invalid file type. Please upload a PNG, JPG, JPEG, or GIF file.', 'danger')
                        return redirect(url_for('profile'))
                    
                    # Create a temporary file
                    import tempfile
                    import os
                    
                    # Create temp directory if it doesn't exist
                    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
                    os.makedirs(temp_dir, exist_ok=True)
                    print(f"Temp directory: {temp_dir}")  # Debug log
                    
                    # Save file to temp directory
                    temp_path = os.path.join(temp_dir, secure_filename(file.filename))
                    file.save(temp_path)
                    print(f"File saved to temp path: {temp_path}")  # Debug log
                    
                    try:
                        # Generate a unique filename for storage
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        storage_filename = f"{session['user']['uid']}_{timestamp}_{secure_filename(file.filename)}"
                        blob_path = f"profile_pics/{storage_filename}"
                        print(f"Storage path: {blob_path}")  # Debug log
                        
                        # Upload to Firebase Storage
                        blob = bucket.blob(blob_path)
                        print("Blob created")  # Debug log
                        
                        # Set content type
                        content_type = f'image/{file_ext}' if file_ext != 'jpg' else 'image/jpeg'
                        blob.content_type = content_type
                        print(f"Content type set: {content_type}")  # Debug log
                        
                        # Upload the file
                        blob.upload_from_filename(temp_path)
                        print("File uploaded successfully")  # Debug log
                        
                        # Make public
                        blob.make_public()
                        print("Blob made public")  # Debug log
                        
                        # Get public URL
                        public_url = blob.public_url
                        print(f"Public URL: {public_url}")  # Debug log
                        updates['photo_url'] = public_url
                        
                    except Exception as storage_error:
                        print(f"Storage error: {str(storage_error)}")  # Debug log
                        print(f"Error type: {type(storage_error)}")  # Debug log
                        raise storage_error
                    finally:
                        # Clean up temp file
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                            print("Temp file cleaned up")  # Debug log
                    
                except Exception as upload_error:
                    print(f"Upload error: {str(upload_error)}")  # Debug log
                    print(f"Error type: {type(upload_error)}")  # Debug log
                    flash('Error uploading profile picture. Please try again.', 'danger')
                    return redirect(url_for('profile'))
        
        # Remove None values
        updates = {k: v for k, v in updates.items() if v is not None}
        
        if updates:
            try:
                user_ref.update(updates)
                # Update session
                user_data = get_user_data(session['user']['uid'])
                update_user_session(user_data)
                flash('Profile updated successfully!', 'success')
            except Exception as update_error:
                print(f"Update error: {str(update_error)}")  # Debug log
                flash('Error updating profile. Please try again.', 'danger')
        else:
            flash('No changes to update', 'info')
            
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"General error: {str(e)}")  # Debug log
        print(f"Error type: {type(e)}")  # Debug log
        flash(f'Error updating profile: {str(e)}', 'danger')
        return redirect(url_for('profile'))

@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'error': 'Email is required'}), 400
            
        email = data['email']
        auth.generate_password_reset_link(email)
        return jsonify({'success': True, 'message': 'Password reset link sent to your email'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

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