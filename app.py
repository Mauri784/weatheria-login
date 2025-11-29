import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import re
import sqlite3
from flask_cors import CORS
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import googlemaps
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()

app = Flask(__name__)
CORS(app)


app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'tu_clave_secreta_super_fuerte')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=30)
jwt = JWTManager(app)


API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')

if not API_KEY:
    raise ValueError("Clave de API no encontrada")

gmaps = googlemaps.Client(key=API_KEY)

# ============================
# ✅ BASE DE DATOS
# ============================

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            status INTEGER NOT NULL
        )
    ''')

    initial_users = [
        ("username1", generate_password_hash("Hola.123"), 1),
        ("username2", generate_password_hash("Hola.123"), 1),
        ("username3", generate_password_hash("Hola.123"), 1),
        ("username4", generate_password_hash("Hola.123"), 1)
    ]

    for username, hashed_password, status in initial_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, status) VALUES (?, ?, ?)",
            (username, hashed_password, status)
        )

    conn.commit()
    conn.close()

# ============================
# ✅ VALIDACIONES
# ============================

def validate_username(username: str) -> bool:
    return bool(username and 3 <= len(username) <= 50 and re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_password(password: str) -> bool:
    return bool(password and len(password) >= 8)

# ============================
# ✅ HEALTH CHECK
# ============================

@app.route('/')
def health_check():
    return jsonify({'message': 'Backend funcionando correctamente'})

# ============================
# ✅ ENVÍO DE REPORTE POR SENDGRID
# ============================

@app.route('/report_flood', methods=['POST'])
def report_flood():
    data = request.get_json()

    required_fields = ['ubicacion', 'fecha', 'temperatura', 'descripcion_clima', 'mensaje']

    if not all(field in data for field in required_fields):
        return jsonify({
            "statusCode": 400,
            "message": "Todos los campos son requeridos"
        })

    ubicacion = data['ubicacion']
    fecha = data['fecha']
    temperatura = data['temperatura']
    descripcion_clima = data['descripcion_clima']
    mensaje = data['mensaje']

    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
    COMPANY_EMAIL = os.environ.get("COMPANY_EMAIL")

    if not all([SENDGRID_API_KEY, SENDER_EMAIL, COMPANY_EMAIL]):
        return jsonify({
            "statusCode": 500,
            "message": "Faltan variables de entorno de SendGrid"
        })

    body = f"""
Se ha recibido un reporte de inundación desde la app Weatheria.

Detalles:
- Ubicación: {ubicacion}
- Fecha: {fecha}
- Temperatura: {temperatura}
- Descripción del Clima: {descripcion_clima}
- Mensaje: {mensaje}

Verificar inmediatamente la zona reportada.
"""

    email = Mail(
        from_email=SENDER_EMAIL,
        to_emails=COMPANY_EMAIL,
        subject="Reporte de Inundación - Weatheria App",
        plain_text_content=body
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(email)

        print("EMAIL ENVIADO - STATUS:", response.status_code)

        return jsonify({
            "statusCode": 200,
            "message": "Reporte enviado exitosamente con SendGrid"
        })

    except Exception as e:
        print("ERROR SENDGRID:", str(e))

        return jsonify({
            "statusCode": 500,
            "message": f"Error al enviar correo: {str(e)}"
        })

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            "statusCode": 400,
            "intData": { "message": "Faltan credenciales" }
        })

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT password, status FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({
            "statusCode": 401,
            "intData": { "message": "Usuario no encontrado" }
        })

    hashed_password, status = user

    if status != 1:
        return jsonify({
            "statusCode": 403,
            "intData": { "message": "Usuario inactivo" }
        })

    if not check_password_hash(hashed_password, password):
        return jsonify({
            "statusCode": 401,
            "intData": { "message": "Contraseña incorrecta" }
        })

    token = create_access_token(identity=username)

    return jsonify({
        "statusCode": 200,
        "intData": {
            "token": token,
            "message": "Login correcto"
        }
    })


# ============================
# ✅ INICIALIZACIÓN
# ============================

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
