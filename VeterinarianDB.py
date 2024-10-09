# Flask SQL Alchemy

# Importing the required libraries

from flask import Flask, jsonify, request, current_app, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, identity_changed, Identity
from flask_login import LoginManager, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from sqlalchemy import create_engine
from sqlalchemy import Table, MetaData, delete
from sqlalchemy.sql import select
import json
import jwt
import datetime
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from logging.config import dictConfig

#############################################################################################################################

# Audit log configuration

dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s | %(module)s >>> %(message)s",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": "audit.log",
                "formatter": "default",
            },
        },
        "root": {"level": "DEBUG", "handlers": ["console", "file"]},
    }
)

#############################################################################################################################

# Database connection

connection_string = 'mysql+pymysql://root:my_password@127.0.0.1:3306/Veterinarian?autocommit=true'
engine = create_engine(connection_string, echo=True)
conn = engine.connect()

metadata = MetaData()

app = Flask(__name__, template_folder='template')

port_number = 7002

#############################################################################################################################

# Get table structures from the database

ap = Table('appointment', metadata, autoload_with=engine)
bill = Table('billing', metadata, autoload_with=engine)
cli = Table('clients', metadata, autoload_with=engine)
ow = Table('owner', metadata, autoload_with=engine)
vet = Table('veterinarian', metadata, autoload_with=engine)

#############################################################################################################################

# Flask configuration

# Configuration

app.config['SECRET_KEY']='supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac2_veterinarian.db'

# Initialize extensions

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
principal = Principal(app)

#############################################################################################################################

# Creation of Users and Roles

# Define User model

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    roles = db.Column(db.String(80))  # A simple column to store user roles as a string

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    user = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

# Define roles
admin_permission = Permission(RoleNeed('admin'))
editor_permission = Permission(RoleNeed('editor'))
user_permission = Permission(RoleNeed('user'))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    # Load the role from JWT
    token = request.headers.get('Authorization').split(' ')[1]
    data = jwt.decode(token, app.config['SECRET_KEY'],
                      algorithms=['HS256'])
    user_role = data['role']

    if user_role:
        identity.provides.add(RoleNeed(user_role))

# Create initial roles and users

@app.before_request
def create_users():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin123'), roles='admin')
        editor_user = User(username='editor', password=generate_password_hash('editor123'), roles='editor')
        regular_user = User(username='regular', password=generate_password_hash('regular123'), roles='user')
        db.session.add(admin_user)
        db.session.add(editor_user)
        db.session.add(regular_user)
        db.session.commit()

#############################################################################################################################

# Decorator to verify JWT tokens

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if the token is passed in the Authorization header

        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1] # Expects Bearer <token>
            
            except IndexError:
                jsonify({'message': 'Token is missing or badly formatted!'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
            user_role = data['role']  # Obtain Rol from token

            # Configuring user identyty for Flask-Principal
            identity_changed.send(current_app._get_current_object(),
                                  identity = Identity(current_user))
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        except IndexError:
            return jsonify({'message': 'Authorization header is missing or malformed!'}), 401
                
        return f(current_user, *args, **kwargs)
            
    return decorated

#############################################################################################################################

# Route to login and receive a token with JWT

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(username=auth.username).first()

    # Verify if the user exists and the password is correct
    if not user or not check_password_hash(user.password, auth.password):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    # Generate JWT token based on the user role
    if user.username == 'admin':
        token = jwt.encode({
            'username': auth.username, 
            'role': 'admin',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm='HS256')
    
    elif user.username == 'editor':
        token = jwt.encode({
            'username': auth.username, 
            'role': 'editor',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm='HS256')
        
    elif user.username == 'regular':
        token = jwt.encode({
            'username': auth.username, 
            'role': 'user',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm='HS256')
    
    else:
        return jsonify({'message': 'User not found!'}),

    return jsonify({'token': token})

# To login and get a token, use the following curl command:

# curl -X POST http://localhost:7002/login -u <username>:<password>

#############################################################################################################################

# Create permisson for multiple roles
class MultiRolePermission(Permission):
    def __init__(self, *roles):
        needs = [RoleNeed(role) for role in roles]
        super().__init__(*needs)

admin_or_editor_permission = MultiRolePermission('admin', 'editor')
admin_or_user_permission = MultiRolePermission('admin', 'user')
all_permission = MultiRolePermission('admin', 'user', 'editor')

# Error message for forbidden access
@app.errorhandler(403)
def forbidden_error(e):
    return jsonify({'message': 'Access forbidden: You do not have the necessary permissions.'}), 403

#############################################################################################################################

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

#############################################################################################################################

@app.before_request
def log_request():
    current_app.logger.info(f"User {current_user.id if current_user else 'Guest'} accessed {request.path} - {request.method}")

#############################################################################################################################

# Codes to GET all the elements from the tables using 'curl

# curl -X GET http://localhost:7002/appointments -H "Authorization: Bearer <token>"
@app.route('/appointments', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_appoitnment(current_user): 
    query = select(ap)
    appointments = conn.execute(query).fetchall()
    return json.dumps([row._asdict() for row in appointments])

# curl -X GET http://localhost:7002/billings -H "Authorization: Bearer <token>"
@app.route('/billings', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_billing(current_user):
    query = select(bill)
    billings = conn.execute(query).fetchall()
    return json.dumps([row._asdict() for row in billings], default=str)

# curl -X GET http://localhost:7002/clients -H "Authorization: Bearer <token>"
@app.route('/clients', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_client(current_user):
    query = select(cli)
    clients = conn.execute(query).fetchall()
    return json.dumps([row._asdict() for row in clients])

# curl -X GET http://localhost:7002/owners -H "Authorization: Bearer <token>"
@app.route('/owners', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_owner(current_user):
    query = select(ow)
    owners = conn.execute(query).fetchall()
    return json.dumps([row._asdict() for row in owners])

# curl -X GET http://localhost:7002/veterinarians -H "Authorization: Bearer <token>"
@app.route('/veterinarians', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_veterinarian(current_user):
    query = select(vet)
    veterinarians = conn.execute(query).fetchall()
    return json.dumps([row._asdict() for row in veterinarians])

#############################################################################################################################

# Codes to GET the elements from the tables by ID using 'curl'

# curl -X GET http://localhost:7002/appointments/id -H "Authorization: Bearer <token>"
@app.route('/appointments/<id>', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_appoitnment_by_id(current_user, id):
    query = select(ap).where(ap.c.appointment_id == id)
    appointments = conn.execute(query).fetchall()
    if appointments != []:
        return json.dumps([row._asdict() for row in appointments])
    return f'Appointment with id {id} not found', 404

# curl -X GET http://localhost:7002/billings/id -H "Authorization: Bearer <token>"
@app.route('/billings/<id>', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_billing_by_id(current_user, id):
    query = select(bill).where(bill.c.billing_id == id)
    billings = conn.execute(query).fetchall()
    if billings != []:
        return json.dumps([row._asdict() for row in billings], default=str)
    return f'Billing with id {id} not found', 404

# curl -X GET http://localhost:7002/clients/id -H "Authorization: Bearer <token>"
@app.route('/clients/<id>', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_client_by_id(current_user, id):
    query = select(cli).where(cli.c.client_id == id)
    clients = conn.execute(query).fetchall()
    if clients != []:
        return json.dumps([row._asdict() for row in clients])
    return f'Client with id {id} not found', 404

# curl -X GET http://localhost:7002/owners/id -H "Authorization: Bearer <token>"
@app.route('/owners/<id>', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_owner_by_id(current_user, id):
    query = select(ow).where(ow.c.owner_id == id)
    owners = conn.execute(query).fetchall()
    if owners != []:
        return json.dumps([row._asdict() for row in owners])
    return f'Owner with id {id} not found', 404

# curl -X GET http://localhost:7002/veterinarians/id -H "Authorization: Bearer <token>"
@app.route('/veterinarians/<id>', methods=["GET"])
@token_required
@all_permission.require(http_exception=403)
def get_veterinarian_by_id(current_user, id):
    query = select(vet).where(vet.c.veterinarian_id == id)
    veterinarians = conn.execute(query).fetchall()
    if veterinarians != []:
        return json.dumps([row._asdict() for row in veterinarians])
    return f'Veterinarian with id {id} not found', 404

#############################################################################################################################

# Codes to INSERT values into the tables using 'curl'

# curl -X POST http://localhost:7002/owners -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"id\": \"6\", \"first_name\": \"Pedro\", \"last_name\": \"Picapiedra\", \"direction\": \"Guayaquil\", \"phone\": \"0984787561\"}"
@app.route("/owners", methods=["POST"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def insert_owner(current_user):
    owner_details = request.get_json()
    id = owner_details["id"]
    first_name = owner_details["first_name"]
    last_name = owner_details["last_name"]
    direction = owner_details["direction"]
    phone = owner_details["phone"]

    # Check if ID already exists
    sel = ow.select().where(ow.c.owner_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Owner with id {id} already exists', 409

    ins = ow.insert().values((id, first_name, last_name, direction, phone))
    conn.execute(ins)
    new_owner = {"id": id, "first_name": first_name, "last_name": last_name, "direction": direction, "phone": phone}
    return jsonify(new_owner), 201

# curl -X POST http://localhost:7002/clients -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"client_id\": \"6\", \"owner_id\": \"5\", \"name\": \"Pichu\", \"species\": \"Cat\", \"breed\": \"Bengala\", \"sex\": \"Male\", \"age\": \"2\", \"treatment\": \"Active\"}"
@app.route("/clients", methods=["POST"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def insert_client(current_user):
    client_details = request.get_json()
    client_id = client_details["client_id"]
    owner_id = client_details["owner_id"]
    name = client_details["name"]
    species = client_details["species"]
    breed = client_details["breed"]
    sex = client_details["sex"]
    age = client_details["age"]
    treatment = client_details["treatment"]

    # Check if client ID already exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Client with id {client_id} already exists', 409

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    ins = cli.insert().values((client_id, owner_id, name, species, breed, sex, age, treatment))
    conn.execute(ins)
    new_client = {"client_id": client_id, "owner_id": owner_id, "name": name, "species": species, "breed": breed, "sex": sex, "age": age, "treatment": treatment}
    return jsonify(new_client), 201

# curl -X POST http://localhost:7002/veterinarians -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"id\": \"5\", \"name\": \"Alan\", \"last_name\": \"Walker\", \"phone\": \"0961452365\", \"direction\": \"Argentina\", \"specialization\": \"Cats\"}"
@app.route("/veterinarians", methods=["POST"])
@token_required
@admin_permission.require(http_exception=403)
def insert_veterinarian(current_user):
    veterinarian_details = request.get_json()
    id = veterinarian_details["id"]
    name = veterinarian_details["name"]
    last_name = veterinarian_details["last_name"]
    phone = veterinarian_details["phone"]
    direction = veterinarian_details["direction"]
    specialization = veterinarian_details["specialization"]

    # Check if ID already exists
    sel = vet.select().where(vet.c.veterinarian_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Veterinarian with id {id} already exists', 409

    ins = vet.insert().values((id, name, last_name, phone, direction, specialization))
    conn.execute(ins)
    new_veterinarian = {"id": id, "name": name, "last_name": last_name, "phone": phone, "direction": direction, "specialization": specialization}
    return jsonify(new_veterinarian), 201

# curl -X POST http://localhost:7002/appointments -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"appointment_id\": \"4\", \"client_id\": \"2\", \"owner_id\": \"4\", \"veterinarian_id\": \"3\", \"date\": \"2023-12-15\", \"time\": \"16h30\", \"reason\": \"Vaccine\"}"
@app.route("/appointments", methods=["POST"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def insert_appointment(current_user):
    appointment_details = request.get_json()
    appointment_id = appointment_details["appointment_id"]
    client_id = appointment_details["client_id"]
    owner_id = appointment_details["owner_id"]
    veterinarian_id = appointment_details["veterinarian_id"]
    date = appointment_details["date"]
    time = appointment_details["time"]
    reason = appointment_details["reason"]

    # Check if appointment ID already exists
    sel = ap.select().where(ap.c.appointment_id == appointment_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Appointment with id {appointment_id} already exists', 409

    # Check if client ID exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Client with id {client_id} not found', 404

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    # Check if owner ID is designated to client ID
    sel = cli.select().where(cli.c.owner_id == owner_id)
    result = conn.execute(sel).fetchall()
    if result:
        pass
    else:
        return f'Owner with ID {owner_id} is not designated to the client with ID {client_id}.', 400

    # Check if veterinarian ID exists
    sel = vet.select().where(vet.c.veterinarian_id == veterinarian_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Veterinarian with id {veterinarian_id} not found', 404

    # Check if the date is valid
    if len(date) > 10 or len(date) < 10:
        return f'Invalid date', 400

    # Check if the time is valid
    if len(time) > 5 or len(time) < 5:
        return f'Invalid time', 400

    ins = ap.insert().values((appointment_id, client_id, owner_id, veterinarian_id, date, time, reason))
    conn.execute(ins)
    new_appointment = {"appointment_id": appointment_id, "client_id": client_id, "owner_id": owner_id, "veterinarian_id": veterinarian_id, "date": date, "time": time, "reason": reason}
    return jsonify(new_appointment), 201

# curl -X POST http://localhost:7002/billings -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"billing_id\": \"7\", \"appointment_id\": \"21\", \"client_id\": \"3\", \"owner_id\": \"2\", \"veterinarian_id\": \"1\", \"date\": \"2023-12-15\", \"service\": \"Vaccine\", \"cost\": \"7.50\"}"
@app.route("/billings", methods=["POST"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def insert_billing(current_user):
    billing_details = request.get_json()
    billing_id = billing_details["billing_id"]
    appointment_id = billing_details["appointment_id"]
    client_id = billing_details["client_id"]
    owner_id = billing_details["owner_id"]
    veterinarian_id = billing_details["veterinarian_id"]
    date = billing_details["date"]
    service = billing_details["service"]
    cost = billing_details["cost"]

    # Check if billing ID already exists
    sel = bill.select().where(bill.c.billing_id == billing_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Billing with id {billing_id} already exists', 409

    # Check if appointment ID exists
    sel = ap.select().where(ap.c.appointment_id == appointment_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Appointment with id {appointment_id} not found', 404

    # Check if client ID exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Client with id {client_id} not found', 404

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    # Check if owner ID is designated to client ID
    sel = cli.select().where(cli.c.owner_id == owner_id)
    result = conn.execute(sel).fetchall()
    if result:
        pass
    else:
        return f'Owner with ID {owner_id} is not designated to the client with ID {client_id}.', 400

    # Check if veterinarian ID exists
    sel = vet.select().where(vet.c.veterinarian_id == veterinarian_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Veterinarian with id {veterinarian_id} not found', 404

    # Check if the date is valid
    if len(date) > 10 or len(date) < 10:
        return f'Invalid date', 400

    ins = bill.insert().values((billing_id, appointment_id, client_id, owner_id, veterinarian_id, date, service, cost))
    conn.execute(ins)
    new_billing = {"billing_id": billing_id, "appointment_id": appointment_id, "client_id": client_id, "owner_id": owner_id, "veterinarian_id": veterinarian_id, "date": date, "service": service, "cost": cost}
    return jsonify(new_billing), 201

#############################################################################################################################

# Codes to UPDATE values from the tables using 'curl'

# curl -X PUT http://localhost:7002/owners/id -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"owner_id\": \"7\", \"first_name\": \"Pedro\", \"last_name\": \"Picapiedra\", \"direction\": \"Guayaquil\", \"phone\": \"0984787561\"}"
@app.route("/owners/<id>", methods=["PUT"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def update_owner(current_user, id):
    owner_details = request.get_json()
    owner_id = owner_details["owner_id"]
    first_name = owner_details["first_name"]
    last_name = owner_details["last_name"]
    direction = owner_details["direction"]
    phone = owner_details["phone"]

    # Check if ID already exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Owner with id {id} already exists', 409

    stmt = ow.update().where(ow.c.owner_id == id).values((owner_id, first_name, last_name, direction, phone))
    conn.execute(stmt)
    updated_owner = {"owner_id": owner_id, "first_name": first_name, "last_name": last_name, "direction": direction, "phone": phone}
    return jsonify(updated_owner), 200

# curl -X PUT http://localhost:7002/clients/id -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"client_id\": \"12\", \"owner_id\": \"5\", \"name\": \"Pichu\", \"species\": \"Cat\", \"breed\": \"Bengala\", \"sex\": \"Male\", \"age\": \"2\", \"treatment\": \"Active\"}"
@app.route("/clients/<id>", methods=["PUT"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def update_client(current_user, id):
    client_details = request.get_json()
    client_id = client_details["client_id"]
    owner_id = client_details["owner_id"]
    name = client_details["name"]
    species = client_details["species"]
    breed = client_details["breed"]
    sex = client_details["sex"]
    age = client_details["age"]
    treatment = client_details["treatment"]

    # Check if client ID already exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Client with id {client_id} already exists', 409

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    stmt = cli.update().where(cli.c.client_id == id).values((client_id, owner_id, name, species, breed, sex, age, treatment))
    conn.execute(stmt)
    updated_client = {"client_id": client_id, "owner_id": owner_id, "name": name, "species": species, "breed": breed, "sex": sex, "age": age, "treatment": treatment}
    return jsonify(updated_client), 200

# curl -X PUT http://localhost:7002/veterinarians/id -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"veterinarian_id\": \"8\", \"name\": \"Alan\", \"last_name\": \"Walker\", \"phone\": \"0961452365\", \"direction\": \"Argentina\", \"specialization\": \"Cats\"}"
@app.route("/veterinarians/<id>", methods=["PUT"])
@token_required
@admin_permission.require(http_exception=403)
def update_veterinarian(current_user, id):
    veterinarian_details = request.get_json()
    veterinarian_id = veterinarian_details["veterinarian_id"]
    name = veterinarian_details["name"]
    last_name = veterinarian_details["last_name"]
    phone = veterinarian_details["phone"]
    direction = veterinarian_details["direction"]
    specialization = veterinarian_details["specialization"]

    # Check if ID already exists
    sel = vet.select().where(vet.c.veterinarian_id == veterinarian_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Veterinarian with id {id} already exists', 409

    stmt = vet.update().where(vet.c.veterinarian_id == id).values((veterinarian_id, name, last_name, phone, direction, specialization))
    conn.execute(stmt)
    updated_veterinarian = {"veterinarian_id": veterinarian_id, "name": name, "last_name": last_name, "phone": phone, "direction": direction, "specialization": specialization}
    return jsonify(updated_veterinarian), 200

# curl -X PUT http://localhost:7002/appointments/id -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"appointment_id\": \"2\", \"client_id\": \"2\", \"owner_id\": \"4\", \"veterinarian_id\": \"3\", \"date\": \"2023-12-15\", \"time\": \"16h30\", \"reason\": \"Vaccine\"}"
@app.route("/appointments/<id>", methods=["PUT"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def update_appointment(current_user, id):
    appointment_details = request.get_json()
    appointment_id = appointment_details["appointment_id"]
    client_id = appointment_details["client_id"]
    owner_id = appointment_details["owner_id"]
    veterinarian_id = appointment_details["veterinarian_id"]
    date = appointment_details["date"]
    time = appointment_details["time"]
    reason = appointment_details["reason"]

    # Check if appointment ID already exists
    sel = ap.select().where(ap.c.appointment_id == appointment_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Appointment with id {appointment_id} already exists', 409

    # Check if client ID exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Client with id {client_id} not found', 404

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    # Check if owner ID is designated to client ID
    sel = cli.select().where(cli.c.owner_id == owner_id)
    result = conn.execute(sel).fetchall()
    if result:
        pass
    else:
        return f'Owner with ID {owner_id} is not designated to the client with ID {client_id}.', 400

    # Check if veterinarian ID exists
    sel = vet.select().where(vet.c.veterinarian_id == veterinarian_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Veterinarian with id {veterinarian_id} not found', 404

    # Check if the date is valid
    if len(date) > 10 or len(date) < 10:
        return f'Invalid date', 400

    # Check if the time is valid
    if len(time) > 5 or len(time) < 5:
        return f'Invalid time', 400

    stmt = ap.update().where(ap.c.appointment_id == id).values((appointment_id, client_id, owner_id, veterinarian_id, date, time, reason))
    conn.execute(stmt)
    updated_appointment = {"appointment_id": appointment_id, "client_id": client_id, "owner_id": owner_id, "veterinarian_id": veterinarian_id, "date": date, "time": time, "reason": reason}
    return jsonify(updated_appointment), 200

# curl -X PUT http://localhost:7002/billings/id -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"billing_id\": \"15\", \"appointment_id\": \"21\", \"client_id\": \"3\", \"owner_id\": \"2\", \"veterinarian_id\": \"1\", \"date\": \"2023-12-15\", \"service\": \"Vaccine\", \"cost\": \"7.50\"}"
@app.route("/billings", methods=["PUT"])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def update_billing(current_user, id):
    billing_details = request.get_json()
    billing_id = billing_details["billing_id"]
    appointment_id = billing_details["appointment_id"]
    client_id = billing_details["client_id"]
    owner_id = billing_details["owner_id"]
    veterinarian_id = billing_details["veterinarian_id"]
    date = billing_details["date"]
    service = billing_details["service"]
    cost = billing_details["cost"]

    # Check if billing ID already exists
    sel = bill.select().where(bill.c.billing_id == billing_id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        return f'Billing with id {billing_id} already exists', 409

    # Check if appointment ID exists
    sel = ap.select().where(ap.c.appointment_id == appointment_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Appointment with id {appointment_id} not found', 404

    # Check if client ID exists
    sel = cli.select().where(cli.c.client_id == client_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Client with id {client_id} not found', 404

    # Check if owner ID exists
    sel = ow.select().where(ow.c.owner_id == owner_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Owner with id {owner_id} not found', 404

    # Check if owner ID is designated to client ID
    sel = cli.select().where(cli.c.owner_id == owner_id)
    result = conn.execute(sel).fetchall()
    if result:
        pass
    else:
        return f'Owner with ID {owner_id} is not designated to the client with ID {client_id}.', 400

    # Check if veterinarian ID exists
    sel = vet.select().where(vet.c.veterinarian_id == veterinarian_id)
    result = conn.execute(sel).fetchone()
    if result is None:
        return f'Veterinarian with id {veterinarian_id} not found', 404

    # Check if the date is valid
    if len(date) > 10 or len(date) < 10:
        return f'Invalid date', 400

    stmt = bill.update().where(bill.c.billing_id == id).values((billing_id, appointment_id, client_id, owner_id, veterinarian_id, date, service, cost))
    conn.execute(stmt)
    updated_billing = {"billing_id": billing_id, "appointment_id": appointment_id, "client_id": client_id, "owner_id": owner_id, "veterinarian_id": veterinarian_id, "date": date, "service": service, "cost": cost}
    return jsonify(updated_billing), 200

#############################################################################################################################

# Codes to DELETE values from the tables using HTTP

# curl -X DELETE http://localhost:7002/owners/id -H "Authorization: Bearer <token>"
@app.route('/owners/<id>', methods=['DELETE'])
@token_required
@admin_permission.require(http_exception=403)
def delete_owner(current_user, id):
    sel = ow.select().where(ow.c.owner_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        stmt = delete(ow).where(ow.c.owner_id == id)
        conn.execute(stmt)
        return f'Owner with ID {id} deleted', 200
    return f'Owner with ID {id} not found', 404

# curl -X DELETE http://localhost:7002/clients/id -H "Authorization: Bearer <token>"
@app.route('/clients/<id>', methods=['DELETE'])
@token_required
@admin_permission.require(http_exception=403)
def delete_client(current_user, id):
    sel = cli.select().where(cli.c.client_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        stmt = delete(cli).where(cli.c.client_id == id)
        conn.execute(stmt)
        return f'Client with ID {id} deleted', 200
    return f'Client with ID {id} not found', 404

# curl -X DELETE http://localhost:7002/veterinarians/id -H "Authorization: Bearer <token>"
@app.route('/veterinarians/<id>', methods=['DELETE'])
@token_required
@admin_permission.require(http_exception=403)
def delete_veterinarian(current_user, id):
    sel = vet.select().where(vet.c.veterinarian_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        stmt = delete(vet).where(vet.c.veterinarian_id == id)
        conn.execute(stmt)
        return f'Veterinarian with ID {id} deleted', 200
    return f'Veterinarian with ID {id} not found', 404

# curl -X DELETE http://localhost:7002/appointments/id -H "Authorization: Bearer <token>"
@app.route('/appointments/<id>', methods=['DELETE'])
@token_required
@admin_or_editor_permission.require(http_exception=403)
def delete_appointment(current_user, id):
    sel = ap.select().where(ap.c.appointment_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        stmt = delete(ap).where(ap.c.appointment_id == id)
        conn.execute(stmt)
        return f'Appointment with ID {id} deleted', 200
    return f'Appointment with ID {id} not found', 404

# curl -X DELETE http://localhost:7002/billings/id -H "Authorization: Bearer <token>"
@app.route('/billings/<id>', methods=['DELETE'])
@token_required
@admin_permission.require(http_exception=403)
def delete_billing(current_user, id):
    sel = bill.select().where(bill.c.billing_id == id)
    result = conn.execute(sel).fetchone()
    if result is not None:
        stmt = delete(bill).where(bill.c.billing_id == id)
        conn.execute(stmt)
        return f'Billing with ID {id} deleted', 200
    return f'Billing with ID {id} not found', 404


if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port = port_number)

