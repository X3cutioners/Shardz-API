import shardz
from flask import Flask, request, jsonify, request, redirect
from flask_cors import CORS

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2500 * 1000 * 1000
# Enable CORS
CORS(app)

# Main route
@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Welcome to Shardz API", "ip": request.remote_addr}), 200

# User Login
@app.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    response = shardz.login(email, password)
    if response:
        return jsonify({"access_token": response}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401
    
# User Registration
@app.route('/register', methods=['POST'])
def register():
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']
    response = shardz.register(name, email, password)
    if response:
        return jsonify({"message": "Registration successful"}),200
    else:
        return jsonify({"message": "User already exists"}), 409

# Forgot Password
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json['email']
    ip_addr = request.json['ip']
    response = shardz.forgot_password(email, ip_addr)
    if response:
        return jsonify({"message": "Password reset link sent to your email"}), 200
    else:
        return jsonify({"message": "Email not found"}), 404

# Verify Email
@app.route('/verify', methods=['POST'])
def verify_email():
    token = request.json['token']
    response = shardz.verify_email(token)
    if response:
        return jsonify({"access_token": response}), 200
    else:
        return jsonify({"message": "Email is not verified"}), 401

# Update Profile
@app.route('/update-profile', methods=['POST'])
def update_profile():
    access_token = request.headers.get('Authorization')
    first_name = request.form['name']
    email = request.form['email']
    file = request.files['file']
    response = shardz.update_profile(access_token, first_name, email, file)
    if response:
        return jsonify({"message": "Profile updated successfully"}), 200
    else:
        return jsonify({"message": "Invalid access token"}), 401

# Update Password
@app.route('/update-password', methods=['POST'])
def update_password():
    access_token = request.headers.get('Authorization')
    new_password = request.json['new_password']
    response = shardz.update_password(access_token, new_password)
    if response:
        return jsonify({"message": "Password updated successfully"}), 200
    else:
        return jsonify({"message": "Invalid access token"}), 401

# Get Profile
@app.route('/profile', methods=['GET'])
def get_profile():
    access_token = request.headers.get('Authorization')
    response = shardz.get_profile(access_token)
    if response:
        return jsonify(response), 200
    else:
        return jsonify({"message": "Invalid access token"}), 401

@app.route('/add-storage', methods=['POST'])
def add_storage():
    access_token = request.headers.get('Authorization')
    response = shardz.add_storage(access_token)
    if response:
        return jsonify(response), 200
    else:
        return jsonify({"message": "Invalid access token"}), 401

@app.route('/oauth/<drive>/callback')
def oauth_callback(drive):
    code = request.args.get('code')
    csrf = request.args.get('state')
    response = shardz.oauth_callback(drive, csrf, code)
    if response:
        return redirect(f"https://shardz.moogi.tech/success?drive={drive}", code=302)
    else:
        return jsonify({"message": "Invalid CSRF token"}), 401

if __name__ == '__main__':
    app.run(debug=True)