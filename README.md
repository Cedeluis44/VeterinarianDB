# VeterinarianDB API
This project is a backend API for managing a veterinary service. It integrates with a MySQL database to handle appointments, billing, clients, and veterinarian records. Additionally, it provides user authentication and role-based access control (RBAC) using Flask.

# Features
- Database Integration: Connects to a MySQL database to manage veterinarian-related data (appointments, clients, billing, etc.).
- Authentication: Uses Flask-Login for user authentication.
- Authorization: Implements Role-Based Access Control (RBAC) using Flask-Principal to control access based on user roles.
- Rate Limiting: Limits the number of requests using Flask-Limiter to prevent abuse.

# Installation
Prerequisites
- Python 3.7+
- MySQL database running with a Veterinarian schema
- Docker (optional) for running a containerized MySQL database
- pip (Python package manager)

Clone the repository

git clone <repository_url>
cd veterinarian-api

Install dependencies

pip install -r requirements.txt

Configure the Database
Edit the connection string in the code to match your MySQL configuration. By default, the connection string is:

connection_string = 'mysql+pymysql://root:my_password@127.0.0.1:3306/Veterinarian?autocommit=true'

Update the username (root), password (my_password), and database URL if necessary.

Set up the SQLite Database for RBAC
Ensure you have SQLite configured correctly to manage user roles and permissions for the RBAC system.

Run the Application
Once everything is set up, you can run the Flask application.

python VeterinarianDB.py

By default, the app will run on port 7002. You can access it at:

http://localhost:7002

# Usage
Endpoints
Here are some examples of the API endpoints:

- Get all appointments:
  curl -v http://localhost:7002/appointments

- Create a new appointment:
curl --header "Content-Type: application/json" --request POST --data "{\"id\": \"6\", \"first_name\": \"Pedro\", \"last_name\": \"Picapiedra\", \"direction\": \"Guayaquil\", \"phone\": \"0984787561\"}" -v http://localhost:7002/owners

- Get client information:
curl -v http://localhost:7002/clients/id

Authentication
The API uses Flask-Login for session-based authentication. To access certain endpoints, you must log in with a valid user.

Rate Limiting
To prevent abuse, some endpoints are rate-limited using Flask-Limiter. Ensure that your API calls respect the rate limits to avoid temporary blocking.
