## Secure Private Chat Application

A secure, private chat application that allows users to communicate with end-to-end encryption and message deletion capabilities.

## Features

- End-to-end encryption for messages
- Private one-to-one chat rooms
- Message deletion functionality
- Anonymous user system
- Secure authentication
- Real-time messaging using WebSocket

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Register a new account or login with existing credentials
2. Once logged in, you'll be automatically assigned a private chat room
3. Share the room ID with your friend to start chatting
4. Messages are encrypted and can only be read by participants in the chat room
5. Use the "Delete All Messages" button to remove all messages from the chat

## Security Features

- All messages are encrypted using Fernet (symmetric encryption)
- Passwords are hashed using bcrypt
- Chat rooms expire after 24 hours
- Messages are stored encrypted in the database
- Each chat room has a unique ID

## Technical Stack

- Backend: Python Flask
- Frontend: HTML, CSS, JavaScript
- Database: SQLite
- Real-time Communication: Socket.IO
- Encryption: cryptography.fernet
- Authentication: Flask-Login

## Note

This is a basic implementation and should be enhanced with additional security measures for production use, such as:
- HTTPS
- Rate limiting
- Input validation
- Session management
- Regular security audits #   t r y 
 
 
