from flask import Flask, request, jsonify
import logging, string, random, re

app = Flask(__name__)
creds = []


@app.route("/creds", methods=["GET"])
def add_password():
    """Endpoint to add a password for testing purposes"""
    password = request.form.get("password", "")

    if not password or len(password.strip()) == 0 or password.isspace():
        print("Password is empty or whitespace, generating random password.")
        password = generate_random_password()

    if len(password.strip()) < 8 or len(password.strip()) > 32:
        print("Password length is invalid:", len(password.strip()))
        return (
            jsonify({"detail": "Password must be between 8 and 32 characters long"}),
            400,
        )

    if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|-~`]+$', password):
        return (
            jsonify(
                {
                    "detail": "Password can only contain alphanumeric characters and special characters"
                }
            ),
            400,
        )

    if password in creds:
        return jsonify({"detail": "Password already exists"}), 400
    else:
        creds.append(password)

    logging.info("Passwords: %s", creds)

    return jsonify(
        {
            "message": "Password added (testing only, not secure for production).",
            "creds": creds,
        }
    )


def generate_random_password(length: int = 12) -> str:
    """Generate a random password with letters, digits, and punctuation."""
    if length < 8 or length > 32:
        raise ValueError("Password length must be between 8 and 32 characters.")

    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for _ in range(length))


if __name__ == "__main__":
    app.run(debug=True)
