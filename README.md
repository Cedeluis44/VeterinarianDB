# VeterinarianDB API
This project is a RESTful API designed to manage a veterinarian system. The API provides functionalities for managing clients, owners, veterinarians, appointments, and billings. It implements secure authentication using JWT, role-based access control (RBAC), rate limiting, and audit logging.

## Features
- **JWT Authentication:** Users must authenticate with JWT tokens to access most API endpoints.
- **Role-Based Access Control (RBAC):** Users have different permissions based on their roles (admin, editor, user).
- **Rate Limiting:** Limits the number of requests to prevent abuse (100 requests per hour).
- **Audit Logging:** Logs all API requests, including failed attempts, for auditing purposes.

## Technologies Used
- **Framework:** Flask
- **Database:** SQLite (configurable to MySQL/PostgreSQL)
- **Authentication:** JWT (JSON Web Tokens)
- **Rate Limiting:** Flask-Limiter
- **Access Control:** Flask-Principal and Flask-Login
- **Audit Logging:** Python’s built-in logging module

## Installation
### Prerequisites
- Python 3.8+
- MySQL database running with a Veterinarian schema
- Docker (optional) for running a containerized MySQL database
- pip (Python package manager)

### Step 1: Clone the repository
```bash
git clone https://github.com/Cedeluis44/VeterinarianDB.git
cd veterinarian-api
```

### Step 2: Set up the virtual environment
Create and activate a virtual environment to isolate dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install dependencies
Install all dependencies listed in *requirements.txt*:

```bash
pip install -r requirements.txt
```

### Step 4: Configure the database
This project is set up to use SQLite by default, but it can be configured to use MySQL or PostgreSQL.
For SQLite, no additional changes are necessary.
For MySQL or PostgreSQL, modify the connection string in the main project file (VeterinarianDB.py):

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://<user>:<password>@<host>:<port>/<db_name>'
```

### Step 5: Initialize the database
Create the tables and insert initial data (roles and users).

```bash
flask db init
flask db migrate
flask db upgrade
```

### Step 6: Run the application
Start the server:

```bash
python VeterinarianDB.py
```

The server will be available at *http://localhost:7002*.

## API Usage

### Authentication
Users must authenticate first to receive a JWT token. Use the following endpoint:
*POST /login*
Description: Authenticates a user and returns a JWT token.

**Request:**

```bash
curl -X POST http://localhost:7002/login -u <username>:<password>
```

**Response:**

```json
{
  "token": "your_jwt_token"
}
```

### Protected Endpoints
To access protected endpoints, include the JWT token in the Authorization header as follows:

```bash
curl -X GET http://localhost:7002/owners -H "Authorization: Bearer <token>"
```

### Available Endpoints
**Clients**
- **GET /clients:** Retrieves all clients.
- **POST /clients:** Creates a new client (restricted to admins or editors).
- **PUT /clients/<id>:** Updates a client by ID (restricted to admins or editors).
- **DELETE /clients/<id>:** Deletes a client by ID (restricted to admins).

**Owners**
- **GET /owners:** Retrieves all owners.
- **POST /owners:** Creates a new owner (restricted to admins or editors).
- **PUT /owners/<id>:** Updates an owner by ID (restricted to admins or editors).
- **DELETE /owners/<id>:** Deletes an owner by ID (restricted to admins).

**Veterinarians**
- **GET /veterinarians:** Retrieves all veterinarians.
- **POST /veterinarians:** Creates a new veterinarian (restricted to admins).
- **PUT /veterinarians/<id>:** Updates a veterinarian by ID (restricted to admins).
- **DELETE /veterinarians/<id>:** Deletes a veterinarian by ID (restricted to admins).

**Appointments**
- **GET /appointments:** Retrieves all appointments.
- **POST /appointments:** Creates a new appointment (restricted to admins or editors).
- **PUT /appointments/<id>:** Updates an appointment by ID (restricted to admins or editors).
- **DELETE /appointments/<id>:** Deletes an appointment by ID (restricted to admins or editors).

**Billings**
- **GET /billings:** Retrieves all billings.
- **POST /billings:** Creates a new billing (restricted to admins or editors).
- **PUT /billings/<id>:** Updates a billing by ID (restricted to admins or editors).
- **DELETE /billings/<id>:** Deletes a billing by ID (restricted to admins).

### Rate limiting
The API is configured to limit requests to 100 per hour. If this limit is exceeded, the API will return a *429 Too Many Requests error*.

```json
{
  "message": "Rate limit exceeded: 100 requests per hour."
}
```

### Audit Logging
All API requests, including successful and failed attempts, are logged to an audit file (audit.log) for monitoring and security purposes.

## Additional Notes:
- Database: You can switch the database engine by modifying the configuration in the application (VeterinarianDB.py).
- Security: JWT is used for authentication, and role-based access control is implemented to secure the API.
