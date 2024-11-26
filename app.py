from flask import Flask, render_template, request, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar la base de datos
db = SQLAlchemy(app)

# Modelo de usuario
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)

@app.route('/')
def home():
    return render_template('signup.html')  

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')
    full_name = request.form.get('full_name')

    if not email or not password or not full_name:
        return render_template('signup.html', error="Todos los campos son obligatorios")
    if len(password) < 8:
        return render_template('signup.html', error="La contraseña debe tener al menos 8 caracteres")
    if len(full_name) < 5:
        return render_template('signup.html', error="El nombre completo debe tener al menos 5 caracteres")
    if User.query.filter_by(email=email).first():
        return render_template('signup.html', error="El correo electrónico ya está registrado")

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=12)

    new_user = User(email=email, password=hashed_password, full_name=full_name)
    db.session.add(new_user)
    db.session.commit()

    return render_template('success.html', name=full_name)

@app.route('/users')
def list_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'email': u.email, 'full_name': u.full_name} for u in users])

if __name__ == '__main__':
    # Asegúrate de que las tablas están creadas antes de ejecutar la app
    with app.app_context():
        db.create_all()
    app.run(debug=True)