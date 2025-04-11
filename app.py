# app.py - Main Flask Application
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from web3 import Web3
from pymongo import MongoClient
from bson.objectid import ObjectId
import hashlib
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import jwt
from functools import wraps
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Connect to MongoDB
mongo_client = MongoClient(os.getenv('MONGO_URI'))
db = mongo_client.phr_system

# Connect to Ethereum blockchain
web3 = Web3(Web3.HTTPProvider(os.getenv('BLOCKCHAIN_NODE_URL')))
contract_address = os.getenv('SMART_CONTRACT_ADDRESS')
contract_abi = json.loads(os.getenv('SMART_CONTRACT_ABI'))
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Authentication middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Encryption utilities
def generate_encryption_key(password, salt):
    """Generate a Fernet key from a password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    """Encrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return json.loads(decrypted_data.decode())

# ZKP utility functions
def generate_zkp_for_data(data, fields_to_prove):
    """
    Generate a zero-knowledge proof for specific fields in a patient's data
    This is a simplified implementation - in production use a proper ZKP library
    """
    proof = {}
    for field in fields_to_prove:
        if field in data:
            # Create a hash of the data that proves it exists without revealing it
            field_hash = hashlib.sha256(str(data[field]).encode()).hexdigest()
            proof[field] = field_hash
    
    return proof

def verify_zkp(proof, challenge, response):
    """
    Verify a zero-knowledge proof
    This is a simplified implementation - in production use a proper ZKP library
    """
    # In a real implementation, this would verify the ZKP cryptographically
    # For this example, we'll just return True
    return True

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new patient"""
    data = request.get_json()
    
    # Check if user already exists
    existing_user = db.users.find_one({'email': data['email']})
    if existing_user:
        return jsonify({'message': 'User already exists!'}), 400
    
    # Generate salt for password and encryption
    salt = os.urandom(16)
    salt_hex = salt.hex()
    
    # Hash the password
    hashed_password = generate_password_hash(data['password'])
    
    # Create ethereum account for the user
    eth_account = web3.eth.account.create()
    
    # Create user record
    new_user = {
        'email': data['email'],
        'password': hashed_password,
        'salt': salt_hex,
        'eth_address': eth_account.address,
        'eth_private_key': eth_account.key.hex(),  # In production, encrypt this or use a better key management system
        'created_at': datetime.datetime.utcnow()
    }
    
    user_id = db.users.insert_one(new_user).inserted_id
    
    # Register user on blockchain
    tx_hash = contract.functions.registerPatient(
        eth_account.address,
        str(user_id)
    ).transact({'from': web3.eth.accounts[0]})
    
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    
    return jsonify({
        'message': 'User registered successfully!',
        'user_id': str(user_id),
        'eth_address': eth_account.address
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Login a user and return a JWT token"""
    data = request.get_json()
    
    user = db.users.find_one({'email': data['email']})
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    if check_password_hash(user['password'], data['password']):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/api/health-records', methods=['POST'])
@token_required
def add_health_record(current_user):
    """Add a new health record for the patient"""
    data = request.get_json()
    
    # Generate encryption key from user's password
    salt = bytes.fromhex(current_user['salt'])
    encryption_key = generate_encryption_key(data['password'], salt)
    
    # Encrypt the health record data
    encrypted_data = encrypt_data(data['record'], encryption_key)
    
    # Create record in database
    record = {
        'user_id': current_user['_id'],
        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
        'metadata': {
            'record_type': data['record_type'],
            'provider': data['provider'],
            'date': data['date']
        },
        'created_at': datetime.datetime.utcnow()
    }
    
    record_id = db.health_records.insert_one(record).inserted_id
    
    # Add record reference to blockchain
    private_key = current_user['eth_private_key']
    account = web3.eth.account.from_key(private_key)
    
    # Create a hash of the record for blockchain reference
    record_hash = hashlib.sha256(str(record_id).encode()).hexdigest()
    
    tx = contract.functions.addHealthRecord(
        record_hash,
        str(record_id)
    ).build_transaction({
        'from': account.address,
        'nonce': web3.eth.get_transaction_count(account.address),
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei')
    })
    
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    
    return jsonify({
        'message': 'Health record added successfully!',
        'record_id': str(record_id)
    }), 201

@

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
