# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities
- Authenticate students, activity leaders, and administrators

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |
| POST   | `/auth/token`                                                     | Exchange configured credentials for a bearer token                  |

Signup and unregister requests require an `Authorization: Bearer <token>` header.
Students may manage only their own email address; activity leaders and administrators may manage participants.

## Authentication Configuration

Set `AUTH_SECRET` to a long random value and optionally set `AUTH_USERS_FILE` to a JSON file containing users.
The default `src/auth_users.json` is intentionally empty. Each user entry must include a role and a PBKDF2-SHA256 password hash:

```json
{
   "teacher": {
      "role": "administrator",
      "password_hash": "pbkdf2_sha256$600000$<base64-salt>$<base64-hash>"
   }
}
```

Generate hashes in an offline setup script; never commit plaintext passwords or the production `AUTH_SECRET`.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
