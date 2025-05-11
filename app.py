from flask import Flask, render_template
import firebase_admin
from firebase_admin import credentials





cred = credentials.Certificate('firebase-admin-config.json')
firebase_admin.initialize_app(cred)

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

