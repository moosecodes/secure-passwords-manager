from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import string, random, re
from typing import Optional

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///creds.db"
db = SQLAlchemy(app)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(32), unique=True, nullable=False)

def extract_password() -> str:
    """Extract password from JSON or form data."""
    if request.is_json:
        data = request.get_json(silent=True)
        if data and "password" in data:
            return data["password"]
    return request.form.get("password", "")

@app.route("/creds", methods=["POST"])
def add_password():
    """Endpoint to add a password for testing purposes."""
    password = extract_password()

    if not password or len(password.strip()) == 0:
        password = generate_random_password()

    is_valid, error = validate_password(password)
    if not is_valid:
        return jsonify({"detail": error}), 400

    # Check if password already exists in the database
    if Credential.query.filter_by(password=password).first():
        return jsonify({"detail": "Password already exists"}), 400

    new_cred = Credential(password=password)
    db.session.add(new_cred)
    db.session.commit()

    return jsonify(
        {
            "message": "Password added (testing only, not secure for production)."
            # "creds": creds,  # Do not return passwords in responses
        }
    )

def validate_password(password: str) -> tuple[bool, Optional[str]]:
    """Validate the password against specific criteria."""
    if len(password) < 8 or len(password) > 32:
        return False, "Password must be between 8 and 32 characters long"
    if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|-~`]+$', password):
        return False, "Password can only contain alphanumeric characters and special characters"
    return True, None

def generate_random_password(length: int = 12) -> str:
    """Generate a random password with letters, digits, and punctuation."""
    if length < 8 or length > 32:
        raise ValueError("Password length must be between 8 and 32 characters.")
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = "".join(random.choice(characters) for _ in range(length))
        is_valid, _ = validate_password(password)
        if is_valid:
            return password

@app.route("/creds", methods=["GET"])
def get_passwords():
    """Endpoint to retrieve all passwords (for testing purposes)."""
    creds = Credential.query.all()
    return jsonify(
        {
            "creds": [cred.password for cred in creds]
        }
    )

@app.route("/creds/<int:id>", methods=["DELETE"])
def delete_password(id: int):
    """Endpoint to delete a password by ID."""
    cred = Credential.query.get(id)
    if not cred:
        return jsonify({"detail": "Credential not found"}), 404

    db.session.delete(cred)
    db.session.commit()
    return jsonify({"message": "Credential deleted successfully"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
