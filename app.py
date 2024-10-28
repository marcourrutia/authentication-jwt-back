from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_migrate import Migrate
from models import db, User
import bcrypt
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwtproyect.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

@app.route('/signup', methods=['POST'])
def signup():
    email = request.json.get("email")
    password = request.json.get("password")
    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    email_exist = User.query.filter_by(email=email).first()
    if email_exist:
        return jsonify({"msg": "Email already use"}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=email)
    return jsonify({"msg": "account created successfully", "token": access_token}), 201

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get("email")
    password = request.json.get("password")

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity=email)
        return jsonify({"msg": "Welcome", "token": access_token}), 200

    return jsonify({"msg": "Verify email or password"}), 401

@app.route('/private', methods=['GET'])
@jwt_required()
def private():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True, port=5050)