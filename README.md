# SecureLog: A Secure Multi-Factor Authentication System 

## Overview

This project implements a secure authentication system with the following features:

* Password hashing using BCrypt
* Challenge–response authentication
* Replay attack prevention
* Modular Flask backend design



---

## Tech Stack

* Python (Flask)
* SQLite (Database)
* Flask-SQLAlchemy
* Flask-Bcrypt
* Flask-CORS

---

## Project Structure

```
project/
│
├── app.py              # Main Flask application
├── extensions.py       # Shared instances (db, bcrypt)
├── models.py           # Database models
├── auth.py             # Authentication APIs
├── utils.py            # Helper functions
└── database.db         # SQLite database (auto-created)
```

---

## Running the Backend

### 1. Clone the repository

```
git clone <repo-link>
cd project
```

### 2. Create virtual environment

```
python -m venv venv
```

### 3. Activate environment

```
venv\Scripts\activate     # Windows
```

### 4. Install dependencies

```
pip install requirements.txt
```

### 5. Run the server

```
python app.py
```

Server runs at:

```
http://127.0.0.1:5000
```

---

## Authentication Flow

### Step 1: User Registration

* User sends username and password
* Password is hashed using BCrypt
* Stored securely in the database

---

### Step 2: Challenge Generation

* User provides username
* Server generates a random challenge (nonce)
* Challenge is stored in the database

---

### Step 3: Challenge–Response Authentication

* Client computes:

  ```
  response = SHA256(password + challenge)
  ```

* Client sends response to server

* Server:

  * Verifies response
  * Marks challenge as used

---

### Step 4: Replay Attack Prevention

* Each challenge is unique and single-use
* Reusing a challenge results in rejection

---

## API Endpoints

### 1. Register User

**POST** `/register`

Request:

```json
{
  "username": "test",
  "password": "1234"
}
```

Response:

```json
{
  "message": "User registered successfully"
}
```

---

### 2. Generate Login Challenge

**POST** `/login-challenge`

Request:

```json
{
  "username": "test"
}
```

Response:

```json
{
  "challenge": "random_string",
  "message": "Challenge generated"
}
```

---

### 3. Verify Login (Challenge–Response)

**POST** `/login-verify`

Request:

```json
{
  "username": "test",
  "challenge": "random_string",
  "response": "hashed_value"
}
```

Response (success):

```json
{
  "message": "Password verified. Proceed to OTP"
}
```

Response (replay attack or invalid):

```json
{
  "message": "Invalid or reused challenge"
}
```

---

## Frontend Integration Guide

Frontend should follow this sequence:

1. Call `/login-challenge`
2. Receive challenge
3. Compute:

   ```
   SHA256(password + challenge)
   ```
4. Send result to `/login-verify`
5. Handle authentication response

---

## OTP Integration Guide

To extend this system with OTP:

After successful `/login-verify`:

1. Generate a 6-digit OTP
2. Store OTP temporarily (database or in-memory)
3. Send OTP via email or display for testing

### New Endpoint

**POST** `/verify-otp`

```json
{
  "username": "test",
  "otp": "123456"
}
```

Flow:

* If OTP is valid, authentication is complete
* Otherwise, reject the request

---

## Security Features

* Password hashing using BCrypt
* Challenge–response authentication
* Replay attack prevention
* No plaintext password transmission


---

## Demo Flow

1. Register a user
2. Generate login challenge
3. Authenticate using challenge-response
4. Attempt replay attack (should fail)
5. OTP verification (after integration)

