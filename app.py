import os
from flask import Flask, send_from_directory
from extensions import db, bcrypt
from flask_cors import CORS
from flask_mail import Mail
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Core Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev_secret_key')

# Flask-Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

db.init_app(app)
bcrypt.init_app(app)
mail = Mail(app)
CORS(app)

from auth import auth_routes
app.register_blueprint(auth_routes)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)