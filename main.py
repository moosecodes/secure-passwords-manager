from flask import Flask, request, jsonify
import logging, string, random, re

app = Flask(__name__)
creds = []


@app.route("/creds", methods=["GET"])
def add_password():
    """Endpoint to add a password for testing purposes"""
    password = ""
    if request.is_json:
        data = request.get_json(silent=True)
        if data and "password" in data:
            password = data["password"]
    else:
        password = request.form.get("password", "")

    if not password or len(password.strip()) == 0:
        password = generate_random_password()

    is_valid, error = validate_password(password)
    if not is_valid:
        return jsonify({"detail": error}), 400

    if password in creds:
        return jsonify({"detail": "Password already exists"}), 400

    creds.append(password)
    # logging.info("Passwords: %s", creds)  # Avoid logging passwords

    return jsonify(
        {
            "message": "Password added (testing only, not secure for production).",
            "creds": creds,
        }
    )

def validate_password(password: str):
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
    password = "".join(random.choice(characters) for _ in range(length))

    is_valid, error = validate_password(password)
    if not is_valid:
        raise ValueError(f"Generated password is invalid: {error}")
    return password


if __name__ == "__main__":
    app.run(debug=True)
