from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
import jwt
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Generate encryption key
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    chat_rooms = db.relationship('ChatRoom', backref='user', lazy=True)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='chat_room', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room_id = os.urandom(16).hex()
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    new_room = ChatRoom(
        room_id=room_id,
        user_id=current_user.id,
        expires_at=expires_at
    )
    db.session.add(new_room)
    db.session.commit()
    
    return jsonify({'room_id': room_id}), 201

@app.route('/join_room/<room_id>', methods=['POST'])
@login_required
def join_room_route(room_id):
    chat_room = ChatRoom.query.filter_by(room_id=room_id).first()
    
    if not chat_room:
        return jsonify({'error': 'Room not found'}), 404
    
    if chat_room.expires_at and chat_room.expires_at < datetime.utcnow():
        return jsonify({'error': 'Room has expired'}), 410
    
    return jsonify({'message': 'Joined room successfully', 'room_id': room_id}), 200

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'User has joined the room.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'User has left the room.'}, room=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    message = data['message']
    
    # Encrypt message
    encrypted_message = cipher_suite.encrypt(message.encode())
    
    # Save to database
    chat_room = ChatRoom.query.filter_by(room_id=room).first()
    if chat_room:
        new_message = Message(
            content=encrypted_message.decode(),
            chat_room_id=chat_room.id
        )
        db.session.add(new_message)
        db.session.commit()
        
        # Decrypt for sending
        decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
        emit('message', {'message': decrypted_message}, room=room)

@app.route('/delete_messages/<room_id>', methods=['POST'])
@login_required
def delete_messages(room_id):
    chat_room = ChatRoom.query.filter_by(room_id=room_id).first()
    if chat_room and chat_room.user_id == current_user.id:
        Message.query.filter_by(chat_room_id=chat_room.id).delete()
        db.session.commit()
        return jsonify({'message': 'Messages deleted successfully'}), 200
    return jsonify({'error': 'Unauthorized'}), 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True) 