# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from functools import wraps
import json
from web3 import Web3
import os
from datetime import datetime, timezone
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from werkzeug.utils import secure_filename
import PyPDF2
import io
from bson import ObjectId  # Make sure this import is present
from bson.errors import InvalidId # Import InvalidId for exception handling
import babel.dates # For date formatting

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Date Formatting Filter --- 
@app.template_filter('formatdatetime')
def format_datetime(value, format='medium'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            # Attempt to parse common string formats if needed
            value = datetime.fromisoformat(value) 
        except ValueError:
             return value # Return original string if parsing fails
             
    if format == 'full':
        format="EEEE, d MMMM y 'at' h:mm:ss a zzzz"
    elif format == 'medium':
        format="MMM d, y, h:mm:ss a"
    elif format == 'short':
         format="M/d/yy, h:mm a"
    elif format == 'date_only':
         format="MMM d, yyyy"
    return babel.dates.format_datetime(value, format)

# Context processor to inject datetime object into templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(timezone.utc)}

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists and has proper permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
if not os.access(UPLOAD_FOLDER, os.W_OK):
    print(f"Warning: Upload folder '{UPLOAD_FOLDER}' is not writable")

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['healthcare_db']
hospitals = db['hospitals']
doctors = db['doctors']
patients = db['patients']
medical_records = db['medical_records']
examinations = db['examinations']
encryption_keys = db['encryption_keys']
pdf_storage = db['pdf_storage']
emergency_logs = db['emergency_logs']
medical_files = db['medical_files']

# Connect to Ganache - local blockchain
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Load smart contract ABI and address
current_dir = os.path.dirname(os.path.abspath(__file__))
contract_abi_path = os.path.join(current_dir, 'contract_abi.json')
with open(contract_abi_path, 'r') as f:
    contract_abi = json.load(f)

contract_address = web3.to_checksum_address('0x5B38Da6a701c568545dCfcB03FcB875f56beddC4')
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Helper functions for encryption
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

def encrypt_data(data, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_pdf_text(pdf_file):
    pdf_reader = PyPDF2.PdfReader(pdf_file)
    text = ""
    for page in pdf_reader.pages:
        text += page.extract_text()
    return text

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Patient-specific decorator
def patient_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'patient':
            flash('Only patients can access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Doctor-specific decorator
def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'doctor':
            flash('Only doctors can access this page', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Define Doctor Specializations
DOCTOR_SPECIALIZATIONS = [
    "Cardiology", "Dermatology", "Neurology", "Oncology", 
    "Pediatrics", "Orthopedics", "Radiology", "General Surgery", 
    "Internal Medicine", "Ophthalmology", "Psychiatry", "Urology",
    "Obstetrics & Gynecology", "Endocrinology", "Gastroenterology",
    "Pulmonology", "Nephrology", "Other"
]

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')

@app.route('/patient_login', methods=['GET', 'POST'])
def patient_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find patient in database
        patient = patients.find_one({'email': email, 'password': password})
        if patient:
            session['user_id'] = str(patient['_id'])
            session['user_type'] = 'patient'
            flash('Login successful!', 'success')
            return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('patient_login.html')

@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find doctor in database
        doctor = doctors.find_one({'email': email, 'password': password})
        if doctor:
            session['user_id'] = str(doctor['_id'])
            session['user_type'] = 'doctor'
            session['name'] = doctor.get('name', '')
            flash('Login successful!', 'success')
            return redirect(url_for('doctor_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('doctor_login.html')

@app.route('/hospital_login', methods=['GET', 'POST'])
def hospital_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find hospital in database
        hospital = hospitals.find_one({'email': email, 'password': password})
        if hospital:
            session['user_id'] = str(hospital['_id'])
            session['user_type'] = 'hospital'
            flash('Login successful!', 'success')
            return redirect(url_for('hospital_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('hospital_login.html')

@app.route('/register_hospital', methods=['GET', 'POST'])
def register_hospital():
    if request.method == 'POST':
        hospital_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'metamask_address': web3.to_checksum_address(request.form['metamask_address']),
            'date_registered': datetime.now()
        }
        
        # Check if hospital already exists
        if hospitals.find_one({'email': hospital_data['email']}):
            flash('Hospital already registered with this email', 'danger')
            return redirect(url_for('register_hospital'))
        
        # Store in MongoDB
        hospitals.insert_one(hospital_data)
        
        # Register on blockchain
        try:
            account = web3.eth.accounts[0]  # Use the first Ganache account
            tx_hash = contract.functions.registerHospital(
                hospital_data['name'],
                hospital_data['metamask_address']
            ).transact({'from': account})
            
            # Wait for transaction receipt
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Hospital registered successfully on blockchain and database', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Blockchain transaction failed: {str(e)}', 'danger')
            return redirect(url_for('register_hospital'))
    
    return render_template('register_hospital.html')

@app.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    # If user is logged in and is a hospital, allow registration
    if 'user_id' in session and session['user_type'] == 'hospital':
        hospital_id = session['user_id']
    else:
        hospital_id = None  # For direct doctor registration
    
    if request.method == 'POST':
        # Collect selected specializations from checkboxes
        selected_specializations = request.form.getlist('specialization_cb')
        
        # Collect and process custom specializations
        other_specialization_input = request.form.get('other_specialization', '').strip()
        custom_specializations = []
        if other_specialization_input:
            # Split by comma, strip whitespace from each item, remove empty strings
            custom_specializations = [spec.strip() for spec in other_specialization_input.split(',') if spec.strip()]
            
        # Combine lists and remove duplicates
        all_specializations = list(dict.fromkeys(selected_specializations + custom_specializations))
        
        # Basic validation: Ensure at least one specialization is present
        if not all_specializations:
            flash('Please select at least one specialization or enter a custom one.', 'danger')
            return render_template('register_doctor.html', specializations=DOCTOR_SPECIALIZATIONS)

        # Prepare data for MongoDB
        doctor_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'specialization': all_specializations,
            'hospital_id': hospital_id,
            'metamask_address': web3.to_checksum_address(request.form['metamask_address']),
            'date_registered': datetime.now()
        }
        
        # Check if doctor already exists
        if doctors.find_one({'email': doctor_data['email']}):
            flash('Doctor already registered with this email', 'danger')
            return render_template('register_doctor.html', specializations=DOCTOR_SPECIALIZATIONS)
        
        # Store in MongoDB
        doctors.insert_one(doctor_data)
        
        # Register on blockchain - Use the *first* specialization for the contract
        blockchain_specialization = all_specializations[0]
        try:
            account = web3.eth.accounts[0]  
            tx_hash = contract.functions.registerDoctor(
                doctor_data['name'],
                blockchain_specialization,
                doctor_data['metamask_address']
            ).transact({'from': account})
            
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Doctor registered successfully on blockchain and database', 'success')
            
            if hospital_id:
                return redirect(url_for('hospital_dashboard'))
            else:
                return redirect(url_for('doctor_login'))
                
        except Exception as e:
            flash(f'Blockchain transaction failed: {str(e)}', 'danger')
            # Roll back the MongoDB insert if blockchain fails
            doctors.delete_one({'email': doctor_data['email']}) 
            return render_template('register_doctor.html', specializations=DOCTOR_SPECIALIZATIONS)
    
    # GET request: Pass the specializations list to the template
    return render_template('register_doctor.html', specializations=DOCTOR_SPECIALIZATIONS)

@app.route('/register_patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        # Generate key pair for encryption
        private_key, public_key = generate_key_pair()
        
        # Process allergies input
        allergies_input = request.form.get('allergies', '').strip()
        allergies_list = []
        if allergies_input:
            # Split by comma, strip whitespace, remove empty strings
            allergies_list = [allergy.strip() for allergy in allergies_input.split(',') if allergy.strip()]

        patient_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'date_of_birth': request.form['date_of_birth'],
            'blood_group': request.form['blood_group'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'emergency_contact': request.form['emergency_contact'],
            'metamask_address': request.form['metamask_address'],
            'public_key': public_key,
            'allergies': allergies_list, # Store the processed list
            'date_registered': datetime.now(),
            'has_selected_providers': False
        }
        
        # Ensure Metamask address is provided (basic check)
        if not patient_data['metamask_address']:
             flash('MetaMask address is required for registration.', 'danger')
             return render_template('register_patient.html')
             
        # Check if patient already exists by email or metamask address
        if patients.find_one({'email': patient_data['email']}):
             flash('Patient already registered with this email.', 'danger')
             return render_template('register_patient.html')
        # Optional: Check if MetaMask address is already registered to avoid conflicts
        # if patients.find_one({'metamask_address': patient_data['metamask_address']}):
        #     flash('This MetaMask address is already associated with another patient.', 'danger')
        #     return render_template('register_patient.html')
             
        # Store in MongoDB
        try:
            patient_id_obj = patients.insert_one(patient_data).inserted_id
            patient_id_str = str(patient_id_obj) # Convert ObjectId to string
        except Exception as db_err:
            flash(f'Error saving patient data: {db_err}', 'danger')
            return render_template('register_patient.html')
            
        # Store private key securely
        encryption_keys.insert_one({
            'patient_id': patient_id_obj, 
            'private_key': private_key,
            'date_created': datetime.now()
        })
        
        # Register on blockchain
        try:
            account = web3.eth.accounts[0]
            # Ensure address is checksummed before sending to contract
            patient_metamask_address_checksum = web3.to_checksum_address(patient_data['metamask_address'])
            
            # Call contract function - Ensure msg.sender is the patient's address
            # This requires the transaction to be initiated by the patient via MetaMask, 
            # not sent from the server's default account (web3.eth.accounts[0])
            # For now, using account[0] as placeholder - needs adjustment for real deployment
            tx_hash = contract.functions.registerPatient(
                patient_data['name'],       
                patient_id_str,           
                patient_data['blood_group'],
                patient_data['public_key'] 
            # ).transact({'from': patient_metamask_address_checksum}) # Ideal case
            ).transact({'from': account}) # Placeholder
            
            web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Patient registered successfully. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error registering on blockchain: {str(e)}', 'danger')
            # Clean up MongoDB entries if blockchain registration fails
            patients.delete_one({"_id": patient_id_obj})
            encryption_keys.delete_one({"patient_id": patient_id_obj})
            return render_template('register_patient.html')
            
    return render_template('register_patient.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_type = session['user_type']
    
    if user_type == 'hospital':
        return redirect(url_for('hospital_dashboard'))
    elif user_type == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif user_type == 'patient':
        return redirect(url_for('patient_dashboard')) # Already exists
    else:
        flash('Unknown user type.', 'danger')
        return redirect(url_for('logout'))

# --- Dedicated Doctor Dashboard Route --- 
@app.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    if 'user_type' not in session or session['user_type'] != 'doctor':
        flash('Access denied. Please login as a doctor.', 'danger')
        return redirect(url_for('login'))
        
    try:
        doctor_id = ObjectId(session['user_id'])
        doctor = doctors.find_one({'_id': doctor_id})
        
        if not doctor:
            flash('Doctor record not found.', 'danger')
            return redirect(url_for('logout'))
            
        # Get patients who have granted access to this doctor
        patients_with_access = patients.find({
            'authorized_doctors': str(doctor_id)
        })
        
        # Get medical records shared with this doctor
        shared_records = medical_records.find({
            'shared_with': str(doctor_id)
        })
        
        return render_template('doctor_dashboard.html', 
                             doctor=doctor,
                             patients=list(patients_with_access),
                             records=list(shared_records))
                             
    except Exception as e:
        flash(f'Error accessing dashboard: {str(e)}', 'danger')
        return redirect(url_for('login'))

# --- Dedicated Hospital Dashboard Route --- 
@app.route('/hospital_dashboard')
@login_required
def hospital_dashboard():
    user_id_str = session['user_id'] # Logged-in hospital's MongoDB ID
    print(f"\n--- Loading Hospital Dashboard for User ID: {user_id_str} ---")
    hospital = None
    registered_doctors = []
    shared_records = [] # Use shared_records instead of accessible_patients
    
    try:
        hospital_id_obj = ObjectId(user_id_str)
        hospital = hospitals.find_one({'_id': hospital_id_obj})
        if not hospital:
            flash('Hospital record not found.', 'danger')
            return redirect(url_for('logout'))
            
        registered_doctors = list(doctors.find({'hospital_id': user_id_str}))

        # --- Fetch Records Shared With This Hospital --- 
        records_cursor = pdf_storage.find({"shared_with": user_id_str})
        temp_records = list(records_cursor)
        print(f"Found {len(temp_records)} records potentially shared with hospital {user_id_str}.")
        
        # Enrich records with patient names
        for record in temp_records:
            try:
                patient_info = patients.find_one({"_id": record.get('patient_id')}, {"name": 1})
                record['patient_name'] = patient_info.get('name', 'Unknown Patient') if patient_info else 'Unknown Patient'
                shared_records.append(record)
            except Exception as patient_fetch_err:
                 print(f"Error fetching patient name for record {record.get('_id')}: {patient_fetch_err}")
                 record['patient_name'] = 'Error Fetching Name'
                 shared_records.append(record)

    except InvalidId:
        flash('Invalid Hospital ID format encountered.', 'danger')
        print(f"Invalid Hospital ID: {user_id_str}")
        return redirect(url_for('logout'))
    except Exception as e:
         flash(f'Error loading hospital dashboard data: {str(e)}', 'danger')
         print(f"!!! Major Error loading hospital dashboard: {e}")
         return redirect(url_for('logout'))

    print(f"Rendering template with {len(shared_records)} shared records.")
    return render_template('hospital_dashboard.html', 
                           hospital=hospital, 
                           registered_doctors=registered_doctors,
                           shared_records=shared_records) # Pass shared_records

@app.route('/view_patients')
@login_required
def view_patients():
    user_type = session['user_type']
    user_id = session['user_id']
    patient_list = [] # Initialize patient_list
    
    if user_type == 'hospital':
        # Assuming 'registered_by' links patient to hospital via hospital's user_id string
        # Adjust if the linking field name or type (ObjectId) is different
        patient_list = list(patients.find({'registered_by': user_id})) 
        
    elif user_type == 'doctor':
        try:
            doctor = doctors.find_one({'_id': ObjectId(user_id)})
            if not doctor or 'metamask_address' not in doctor:
                flash('Doctor record or MetaMask address not found.', 'danger')
                return redirect(url_for('dashboard'))

            doctor_address = doctor['metamask_address']
            
            # Fetch all potentially relevant patients 
            # In a large system, pagination or filtering would be needed here.
            all_patients_cursor = patients.find()
            
            accessible_patients = []
            for patient in all_patients_cursor:
                try:
                    # Convert patient MongoDB _id to string for contract interaction
                    patient_id_str = str(patient['_id']) 
                    
                    # Check access using blockchain
                    has_access = contract.functions.checkAccess(
                        patient_id_str, 
                        doctor_address
                    ).call() 
                    
                    if has_access:
                        accessible_patients.append(patient)
                except Exception as contract_err:
                    # Log error or notify admin, but continue checking other patients
                    print(f"Error checking access for patient {patient['_id']} for doctor {doctor_address}: {contract_err}") 
                    # Optionally flash a generic warning once: flash('Could not verify access for all patients.', 'warning')
                    
            patient_list = accessible_patients

        except Exception as e:
            flash(f'Error retrieving data: {str(e)}', 'danger')
            return redirect(url_for('dashboard'))
            
    else: # User is a patient or an unknown type
        flash('You do not have permission to view this page.', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('view_patients.html', patients=patient_list)

@app.route('/patient_details/<patient_id>')
@login_required
def patient_details(patient_id):
    patient = patients.find_one({'_id': patient_id})
    if not patient:
        flash('Patient not found', 'danger')
        return redirect(url_for('view_patients'))
    
    # Check if user has access to this patient's data
    try:
        has_access = contract.functions.checkAccess(
            str(patient_id),
            session.get('metamask_address', '0x0')
        ).call()
        
        if not has_access:
            flash('You do not have access to this patient\'s data', 'danger')
            return redirect(url_for('view_patients'))
    except Exception as e:
        flash(f'Error checking access: {str(e)}', 'danger')
        return redirect(url_for('view_patients'))
    
    medical_history = list(medical_records.find({'patient_id': patient_id}))
    examinations_list = list(examinations.find({'patient_id': patient_id}))
    
    return render_template('patient_details.html', patient=patient, 
                          medical_history=medical_history, examinations=examinations_list)

@app.route('/add_medical_record/<patient_id>', methods=['GET', 'POST'])
@login_required
def add_medical_record(patient_id):
    if request.method == 'POST':
        try:
            # Get patient's public key
            public_key = contract.functions.getPatientPublicKey(patient_id).call()
            
            # Encrypt the record
            record_data = {
                'condition': request.form['condition'],
                'medication': request.form['medication'],
                'allergies': request.form['allergies'],
                'notes': request.form['notes']
            }
            encrypted_data = encrypt_data(json.dumps(record_data), public_key)
            
            # Store encrypted data on blockchain
            account = web3.eth.accounts[0]
            tx_hash = contract.functions.storeEncryptedRecord(
                patient_id,
                encrypted_data
            ).transact({'from': account})
            
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Medical record added and encrypted successfully', 'success')
            return redirect(url_for('patient_details', patient_id=patient_id))
        except Exception as e:
            flash(f'Error adding medical record: {str(e)}', 'danger')
            return redirect(url_for('add_medical_record', patient_id=patient_id))
    
    return render_template('add_medical_record.html', patient_id=patient_id)

@app.route('/add_examination/<patient_id>', methods=['GET', 'POST'])
@login_required
def add_examination(patient_id):
    if session['user_type'] != 'doctor':
        flash('Only doctors can add examinations', 'danger')
        return redirect(url_for('patient_details', patient_id=patient_id))
    
    patient = patients.find_one({'_id': patient_id})
    if not patient:
        flash('Patient not found', 'danger')
        return redirect(url_for('view_patients'))
    
    if request.method == 'POST':
        exam_data = {
            'patient_id': patient_id,
            'doctor_id': session['user_id'],
            'symptoms': request.form['symptoms'],
            'diagnosis': request.form['diagnosis'],
            'treatment': request.form['treatment'],
            'notes': request.form['notes'],
            'date_examined': datetime.now()
        }
        
        # Store in MongoDB
        exam_id = examinations.insert_one(exam_data).inserted_id
        
        # Add to blockchain
        try:
            account = web3.eth.accounts[0]  # Use the first Ganache account
            tx_hash = contract.functions.addExamination(
                str(patient_id),
                str(exam_id),
                exam_data['diagnosis'],
                datetime.now().strftime("%Y-%m-%d")
            ).transact({'from': account})
            
            # Wait for transaction receipt
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Examination added successfully on blockchain and database', 'success')
            return redirect(url_for('patient_details', patient_id=patient_id))
        except Exception as e:
            flash(f'Blockchain transaction failed: {str(e)}', 'danger')
            return redirect(url_for('add_examination', patient_id=patient_id))
    
    return render_template('add_examination.html', patient=patient)

@app.route('/grant_access/<patient_id>', methods=['POST'])
@login_required
@patient_required
def grant_access(patient_id):
    try:
        user_address = web3.to_checksum_address(request.form['address'])
        duration = int(request.form['duration'])
        allowed_fields = request.form.getlist('fields')
        is_doctor = request.form.get('user_type') == 'doctor'
        is_hospital = request.form.get('user_type') == 'hospital'
        
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.grantAccess(
            user_address,
            duration,
            allowed_fields,
            is_doctor,
            is_hospital
        ).transact({'from': account})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Access granted successfully', 'success')
    except Exception as e:
        flash(f'Error granting access: {str(e)}', 'danger')
    
    return redirect(url_for('patient_dashboard'))

@app.route('/revoke_access/<patient_id>', methods=['POST'])
@login_required
@patient_required
def revoke_access(patient_id):
    try:
        user_address = web3.to_checksum_address(request.form['address'])
        
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.revokeAccess(user_address).transact({'from': account})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Access revoked successfully', 'success')
    except Exception as e:
        flash(f'Error revoking access: {str(e)}', 'danger')
    
    return redirect(url_for('patient_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/blockchain_data')
@login_required
def blockchain_data():
    try:
        # Get contract information
        contract_info = {
            'address': contract_address,
            'total_hospitals': len(web3.eth.accounts),  # This is a simple example
            'network': web3.eth.chain_id,
            'block_number': web3.eth.block_number
        }
        
        # Get recent transactions
        latest_block = web3.eth.block_number
        recent_transactions = []
        for i in range(latest_block, max(0, latest_block - 10), -1):
            block = web3.eth.get_block(i, full_transactions=True)
            for tx in block.transactions:
                if tx.to and tx.to.lower() == contract_address.lower():
                    recent_transactions.append({
                        'hash': tx.hash.hex(),
                        'from': tx['from'],
                        'to': tx.to,
                        'value': web3.from_wei(tx.value, 'ether'),
                        'block': i
                    })
        
        # Get events
        events = []
        # Hospital events
        hospital_registered_filter = contract.events.HospitalRegistered.create_filter(from_block=0)
        hospital_events = hospital_registered_filter.get_all_entries()
        for event in hospital_events:
            events.append({
                'type': 'HospitalRegistered',
                'name': event.args.name,
                'address': event.args.walletAddress,
                'block': event.blockNumber
            })
        
        # Doctor events
        doctor_registered_filter = contract.events.DoctorRegistered.create_filter(from_block=0)
        doctor_events = doctor_registered_filter.get_all_entries()
        for event in doctor_events:
            events.append({
                'type': 'DoctorRegistered',
                'name': event.args.name,
                'specialization': event.args.specialization,
                'address': event.args.walletAddress,
                'block': event.blockNumber
            })
        
        # Examination events
        examination_filter = contract.events.ExaminationAdded.create_filter(from_block=0)
        examination_events = examination_filter.get_all_entries()
        for event in examination_events:
            events.append({
                'type': 'ExaminationAdded',
                'patient_id': event.args.patientId,
                'examination_id': event.args.examinationId,
                'diagnosis': event.args.diagnosis,
                'date': event.args.date,
                'block': event.blockNumber
            })
        
        return render_template('blockchain_data.html', 
                             contract_info=contract_info,
                             transactions=recent_transactions,
                             events=events)
    except Exception as e:
        flash(f'Error fetching blockchain data: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/setup_encryption/<patient_id>', methods=['GET', 'POST'])
@login_required
def setup_encryption(patient_id):
    if request.method == 'POST':
        try:
            # Generate new key pair
            private_key, public_key = generate_key_pair()
            
            # Store private key securely (in a real application, this would be encrypted)
            encryption_keys.insert_one({
                'patient_id': patient_id,
                'private_key': private_key,
                'date_created': datetime.now()
            })
            
            # Register public key on blockchain
            account = web3.eth.accounts[0]
            tx_hash = contract.functions.registerPatient(
                request.form['name'],
                patient_id,
                request.form['blood_group'],
                public_key
            ).transact({'from': account})
            
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            flash('Encryption setup completed successfully', 'success')
            return redirect(url_for('patient_details', patient_id=patient_id))
        except Exception as e:
            flash(f'Error setting up encryption: {str(e)}', 'danger')
            return redirect(url_for('setup_encryption', patient_id=patient_id))
    
    return render_template('setup_encryption.html', patient_id=patient_id)

@app.route('/grant_field_access/<patient_id_url>', methods=['POST'])
@login_required
@patient_required # Ensures only logged-in patients can access
def grant_field_access(patient_id_url):
    # Verify the URL ID matches the logged-in patient
    logged_in_patient_id_str = session['user_id']
    if patient_id_url != logged_in_patient_id_str:
        flash('Authorization error: Mismatch in patient ID.', 'danger')
        return redirect(url_for('patient_dashboard'))
        
    logged_in_patient_id_obj = ObjectId(logged_in_patient_id_str)
    
    address_input = request.form.get('address', '').strip()
    duration_days_input = request.form.get('duration', '0')
    allowed_fields = request.form.getlist('fields')

    # --- Input Validation ---
    if not address_input or not duration_days_input or not allowed_fields:
        flash('Missing required fields: Address, Duration, and Allowed Fields.', 'danger')
        return redirect(url_for('patient_dashboard'))

    try:
        duration_days = int(duration_days_input)
        if duration_days <= 0:
            raise ValueError("Duration must be a positive number of days.")
        # Convert duration to seconds for the smart contract
        duration_seconds = duration_days * 24 * 60 * 60 
    except ValueError as e:
        flash(f'Invalid duration: {e}', 'danger')
        return redirect(url_for('patient_dashboard'))

    try:
        # Validate and checksum the target address
        address_to_grant = web3.to_checksum_address(address_input)
    except ValueError:
        flash(f'Invalid Ethereum address format: "{address_input}". Please enter a valid address starting with 0x.', 'danger')
        return redirect(url_for('patient_dashboard'))
    # ------------------------
    
    try:
        # Fetch the logged-in patient's MetaMask address for sending the transaction
        patient = patients.find_one({'_id': logged_in_patient_id_obj}, {'metamask_address': 1})
        if not patient or 'metamask_address' not in patient:
            flash('Your MetaMask address is not linked. Cannot send transaction.', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        granting_patient_metamask_address = web3.to_checksum_address(patient['metamask_address'])

        # Call the contract function with the logged-in patient's ID string
        tx_hash = contract.functions.grantAccess(
            logged_in_patient_id_str, # Patient ID whose data is accessed (the logged-in user)
            address_to_grant,       # Address receiving access (validated hex)
            duration_seconds,       # Duration in seconds
            allowed_fields          # Fields allowed
        # ).transact({'from': granting_patient_metamask_address}) # Ideal case: Tx sent by patient via MetaMask
        ).transact({'from': web3.eth.accounts[0]}) # Placeholder: Tx sent by server account
        
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Field access granted successfully!', 'success')
    except Exception as e:
        # Catch potential contract errors or other issues
        flash(f'Error granting field access: {str(e)}', 'danger')
    
    # Redirect back to the patient dashboard (no ID needed as it uses session)
    return redirect(url_for('patient_dashboard'))

@app.route('/create_research_agreement/<patient_id>', methods=['POST'])
@login_required
def create_research_agreement(patient_id):
    try:
        researcher_address = web3.to_checksum_address(request.form['researcher_address'])
        purpose = request.form['purpose']
        compensation = int(request.form['compensation'])
        duration = int(request.form['duration'])
        allowed_fields = request.form.getlist('fields')
        
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.createResearchAgreement(
            patient_id,
            researcher_address,
            purpose,
            compensation,
            duration,
            allowed_fields
        ).transact({'from': account})
        
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Research agreement created successfully', 'success')
    except Exception as e:
        flash(f'Error creating research agreement: {str(e)}', 'danger')
    
    return redirect(url_for('patient_details', patient_id=patient_id))

@app.route('/store_encrypted_record/<patient_id>', methods=['POST'])
@login_required
def store_encrypted_record(patient_id):
    try:
        # Get patient's public key from blockchain
        public_key = contract.functions.getPatientPublicKey(patient_id).call()
        
        # Encrypt the record
        record_data = {
            'condition': request.form['condition'],
            'medication': request.form['medication'],
            'allergies': request.form['allergies'],
            'notes': request.form['notes']
        }
        encrypted_data = encrypt_data(json.dumps(record_data), public_key)
        
        # Store encrypted data on blockchain
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.storeEncryptedRecord(
            patient_id,
            encrypted_data
        ).transact({'from': account})
        
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Encrypted record stored successfully', 'success')
    except Exception as e:
        flash(f'Error storing encrypted record: {str(e)}', 'danger')
    
    return redirect(url_for('patient_details', patient_id=patient_id))

@app.route('/verify_zkp/<patient_id>', methods=['POST'])
@login_required
def verify_zero_knowledge_proof(patient_id):
    try:
        proof = request.form['proof']
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.verifyZeroKnowledgeProof(
            patient_id,
            proof.encode()
        ).transact({'from': account})
        
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Zero-knowledge proof verified successfully', 'success')
    except Exception as e:
        flash(f'Error verifying zero-knowledge proof: {str(e)}', 'danger')
    
    return redirect(url_for('patient_details', patient_id=patient_id))

@app.route('/upload_medical_file', methods=['GET', 'POST'])
@login_required
@doctor_required
def upload_medical_file():
    if request.method == 'GET':
        # Get list of patients that the doctor has access to
        doctor_id = ObjectId(session['user_id'])
        patients_with_access = patients.find({
            'authorized_doctors': str(doctor_id)
        })
        return render_template('upload_medical_file.html', patients=patients_with_access)
    
    if request.method == 'POST':
        try:
            # Get form data
            patient_id = request.form.get('patient_id')
            file_type = request.form.get('file_type')
            description = request.form.get('description')
            file = request.files.get('file')
            
            if not all([patient_id, file_type, file]):
                flash('Please fill in all required fields', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Validate file
            if not file.filename:
                flash('No file selected', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Check file size (10MB limit)
            if len(file.read()) > 10 * 1024 * 1024:  # 10MB in bytes
                flash('File size exceeds 10MB limit', 'danger')
                return redirect(url_for('upload_medical_file'))
            file.seek(0)  # Reset file pointer
            
            # Generate unique filename
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            
            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join(app.root_path, 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)
            
            # Save file
            file_path = os.path.join(upload_dir, unique_filename)
            file.save(file_path)
            
            # Store file metadata in database
            medical_files.insert_one({
                'patient_id': ObjectId(patient_id),
                'doctor_id': ObjectId(session['user_id']),
                'file_type': file_type,
                'description': description,
                'filename': unique_filename,
                'original_filename': filename,
                'upload_date': datetime.now(),
                'file_path': file_path
            })
            
            flash('File uploaded successfully', 'success')
            return redirect(url_for('doctor_dashboard'))
            
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            return redirect(url_for('upload_medical_file'))

@app.route('/patient_dashboard')
@login_required
@patient_required
def patient_dashboard():
    try:
        patient_id = ObjectId(session['user_id'])
        patient = patients.find_one({'_id': patient_id})
    except Exception as e:
        flash(f'Error retrieving patient data: {e}', 'danger')
        return redirect(url_for('logout'))

    if not patient:
        flash('Patient data not found.', 'danger')
        return redirect(url_for('logout'))

    # --- Check if patient needs to select providers --- 
    if not patient.get('has_selected_providers', False): 
        try:
            all_hospitals = list(hospitals.find({}, {'name': 1, '_id': 1})) 
            all_doctors = list(doctors.find({}, {'name': 1, '_id': 1, 'specialization': 1})) 
            for h in all_hospitals: h['_id'] = str(h['_id'])
            for d in all_doctors: d['_id'] = str(d['_id'])
            flash('Please select the hospital and doctor(s) you have visited previously.', 'info')
            return render_template('select_providers.html', 
                                 patient=patient, 
                                 hospitals=all_hospitals, 
                                 doctors=all_doctors)
        except Exception as e:
             flash(f'Error fetching provider lists: {e}', 'danger')
             pass 
    
    # --- Render Normal Dashboard --- 
    records = []
    try:
        records = list(pdf_storage.find({'patient_id': patient_id})) 
    except Exception as e:
        flash(f'Error fetching medical records: {e}', 'danger')
    
    # --- Fetch providers for suggestion datalist --- 
    all_providers_for_suggestion = []
    try:
        # This part remains the same, just for the datalist suggestion
        docs = list(doctors.find({}, {'_id': 0, 'name': 1, 'metamask_address': 1}))
        for doc in docs:
            if 'metamask_address' in doc:
                all_providers_for_suggestion.append({
                    'value': doc['metamask_address'],
                    'label': f"{doc['name']} (Doctor)"
                })
        hosps = list(hospitals.find({}, {'_id': 0, 'name': 1, 'metamask_address': 1}))
        for hosp in hosps:
             if 'metamask_address' in hosp:
                all_providers_for_suggestion.append({
                    'value': hosp['metamask_address'],
                    'label': f"{hosp['name']} (Hospital)"
                })
    except Exception as e:
        flash(f'Error fetching providers for suggestions: {str(e)}', 'warning')
    
    # --- Fetch names for initially selected providers (for display) --- 
    selected_hospital_name = None
    selected_doctors_info = []
    try:
        selected_hospital_id_str = patient.get('selected_hospital_id')
        if selected_hospital_id_str:
            hospital_info = hospitals.find_one({'_id': ObjectId(selected_hospital_id_str)}, {'name': 1})
            if hospital_info:
                selected_hospital_name = hospital_info.get('name')

        selected_doctor_ids_list = patient.get('selected_doctor_ids')
        if selected_doctor_ids_list and isinstance(selected_doctor_ids_list, list):
             for doc_id_str in selected_doctor_ids_list:
                 doctor_info = doctors.find_one({'_id': ObjectId(doc_id_str)}, {'name': 1})
                 if doctor_info:
                     selected_doctors_info.append({
                         'id': doc_id_str,
                         'name': doctor_info.get('name', 'Name Missing')
                     })
                 else:
                     selected_doctors_info.append({'id': doc_id_str, 'name': 'Doctor Not Found'})
    except InvalidId:
        print("Error: Invalid ObjectId found in selected provider IDs.")
        # Handle error appropriately, maybe flash a warning
    except Exception as e:
        print(f"Error fetching selected provider names: {e}")
        # Handle error, maybe flash a warning

    # --- Fetch All Doctors/Hospitals for Sharing Dropdowns --- 
    all_doctors_list = []
    all_hospitals_list = []
    try:
        # Fetch name and _id, convert _id to string for template forms
        all_doctors_raw = list(doctors.find({}, {'_id': 1, 'name': 1}))
        all_doctors_list = [{'_id': str(doc['_id']), 'name': doc['name']} for doc in all_doctors_raw]
        
        all_hospitals_raw = list(hospitals.find({}, {'_id': 1, 'name': 1}))
        all_hospitals_list = [{'_id': str(hosp['_id']), 'name': hosp['name']} for hosp in all_hospitals_raw]
        
    except Exception as e:
        print(f"Error fetching provider lists for sharing: {e}")
        # Continue without lists, sharing might fail gracefully or show error in template

    return render_template('patient_dashboard.html',
                         patient=patient,
                         records=records,
                         provider_suggestions=all_providers_for_suggestion,
                         selected_hospital_name=selected_hospital_name, 
                         selected_doctors_info=selected_doctors_info, 
                         all_doctors=all_doctors_list,     # Pass full list for sharing
                         all_hospitals=all_hospitals_list # Pass full list for sharing
                         )

@app.route('/patient/select_providers', methods=['POST'])
@login_required
@patient_required
def select_providers_submit():
    patient_id = ObjectId(session['user_id'])
    patient = patients.find_one({'_id': patient_id})

    if not patient:
        flash('Patient not found.', 'danger')
        return redirect(url_for('logout'))

    if patient.get('has_selected_providers', False):
        flash('Provider selection already completed.', 'info')
        return redirect(url_for('patient_dashboard'))
        
    selected_hospital_id = request.form.get('hospital_id')
    selected_doctor_ids = request.form.getlist('doctor_ids')

    if not selected_hospital_id:
        flash('Please select a hospital.', 'danger')
        all_hospitals = list(hospitals.find({}, {'name': 1, '_id': 1}))
        all_doctors = list(doctors.find({}, {'name': 1, '_id': 1, 'specialization': 1}))
        for h in all_hospitals: h['_id'] = str(h['_id'])
        for d in all_doctors: d['_id'] = str(d['_id'])
        return render_template('select_providers.html', 
                             patient=patient, 
                             hospitals=all_hospitals, 
                             doctors=all_doctors)
    
    update_data = {
        'selected_hospital_id': selected_hospital_id, 
        'selected_doctor_ids': selected_doctor_ids,   
        'has_selected_providers': True
    }
    
    try:
        patients.update_one({'_id': patient_id}, {'$set': update_data})
        
        # --- Grant initial blockchain access --- 
        patient_metamask_address_str = patient.get('metamask_address')
        if patient_metamask_address_str:
            try:
                # Ensure patient address is checksummed for 'from' if used, though placeholder uses account[0]
                granting_patient_address = web3.to_checksum_address(patient_metamask_address_str)
                
                access_duration = 365 * 24 * 60 * 60 # 1 year in seconds
                allowed_fields = ['personal_info', 'medical_records', 'examinations'] # Example
                print(f"Attempting initial grant from patient: {granting_patient_address}")

                # Grant access to hospital
                hospital_doc = hospitals.find_one({'_id': ObjectId(selected_hospital_id)}, {'metamask_address': 1, 'name': 1})
                if hospital_doc and 'metamask_address' in hospital_doc:
                    try:
                        # FIX: Checksum hospital address before passing to grantAccess
                        hospital_address_checksum = web3.to_checksum_address(hospital_doc['metamask_address'])
                        print(f"  Granting access to Hospital: {hospital_doc['name']} ({hospital_address_checksum})")
                        
                        # FIX: Use Patient's MetaMask address as first argument if contract expects it
                        # Assuming grantAccess expects: patientAddress, granteeAddress, duration, fields
                        tx_hash_hosp = contract.functions.grantAccess(
                            granting_patient_address,     # Patient whose data is being accessed
                            hospital_address_checksum,    # Grantee address
                            access_duration,
                            allowed_fields 
                        ).transact({'from': web3.eth.accounts[0]}) # Placeholder: Server sends tx
                        web3.eth.wait_for_transaction_receipt(tx_hash_hosp)
                        flash(f'Initial access granted to hospital: {hospital_doc["name"]}', 'success')
                    except ValueError as checksum_err:
                        flash(f"Failed to grant initial access to hospital {hospital_doc.get('name', '')} due to invalid address: {checksum_err}", 'danger')
                        print(f"Checksum Error (Hospital Grant): {checksum_err}")
                    except Exception as grant_err_hosp:
                        flash(f'Failed to grant initial blockchain access to hospital {hospital_doc.get("name", "")}: {grant_err_hosp}', 'warning')
                        print(f"Contract Error (Hospital Grant): {grant_err_hosp}")
                else:
                     print("Selected hospital not found or missing MetaMask address.")
            
                # Grant access to selected doctors
                for doc_id_str in selected_doctor_ids:
                    doctor_doc = doctors.find_one({'_id': ObjectId(doc_id_str)}, {'metamask_address': 1, 'name': 1})
                    if doctor_doc and 'metamask_address' in doctor_doc:
                         try:
                            # FIX: Checksum doctor address before passing to grantAccess
                            doctor_address_checksum = web3.to_checksum_address(doctor_doc['metamask_address'])
                            print(f"  Granting access to Doctor: {doctor_doc['name']} ({doctor_address_checksum})")
                            
                            # FIX: Use Patient's MetaMask address as first argument if contract expects it
                            tx_hash_doc = contract.functions.grantAccess(
                                granting_patient_address,    # Patient whose data is being accessed
                                doctor_address_checksum,   # Grantee address
                                access_duration,
                                allowed_fields
                            ).transact({'from': web3.eth.accounts[0]}) # Placeholder: Server sends tx
                            web3.eth.wait_for_transaction_receipt(tx_hash_doc)
                            flash(f'Initial access granted to doctor: {doctor_doc["name"]}', 'success')
                         except ValueError as checksum_err:
                             flash(f"Failed to grant initial access to doctor {doctor_doc.get('name', '')} due to invalid address: {checksum_err}", 'danger')
                             print(f"Checksum Error (Doctor Grant): {checksum_err}")
                         except Exception as grant_err_doc:
                            flash(f'Failed to grant initial blockchain access to doctor {doctor_doc.get("name", "")}: {grant_err_doc}', 'warning')
                            print(f"Contract Error (Doctor Grant): {grant_err_doc}")
                    else:
                         print(f"Selected doctor ID {doc_id_str} not found or missing MetaMask address.")
            
            except ValueError as patient_checksum_err:
                flash(f"Error processing patient address for initial grant: {patient_checksum_err}", 'danger')
                print(f"Checksum Error (Patient Address for Grant): {patient_checksum_err}")
        else:
             print("Patient address not found, skipping initial blockchain grant.")
             flash("Provider selection saved, but initial blockchain access grant skipped (patient address missing).", 'warning')
        # --------------------------------------------------
        
        flash('Provider selection saved successfully!', 'success')
        return redirect(url_for('patient_dashboard'))
        
    except Exception as e:
        flash(f'Error saving provider selection: {e}', 'danger')
        print(f"!!! Major Error saving provider selection: {e}")
        # Re-render form on error
        all_hospitals = list(hospitals.find({}, {'name': 1, '_id': 1}))
        all_doctors = list(doctors.find({}, {'name': 1, '_id': 1, 'specialization': 1}))
        for h in all_hospitals: h['_id'] = str(h['_id'])
        for d in all_doctors: d['_id'] = str(d['_id'])
        return render_template('select_providers.html', 
                             patient=patient, 
                             hospitals=all_hospitals, 
                             doctors=all_doctors)

@app.route('/delete_record/<record_id>', methods=['POST'])
@login_required
@patient_required
def delete_record(record_id):
    try:
        record_oid = ObjectId(record_id)
        patient_id = ObjectId(session['user_id'])

        # Find the record in MongoDB
        record = pdf_storage.find_one({'_id': record_oid})

        if not record:
            flash('Record not found.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Security Check: Ensure the logged-in patient owns this record
        if record.get('patient_id') != patient_id:
            flash('Unauthorized: You do not own this record.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # --- Deletion Process ---
        file_path = record.get('file_path')
        filename = record.get('filename')

        # 1. Delete the physical file (if path exists and file exists)
        deleted_file = False
        if file_path:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                    deleted_file = True
                else:
                    print(f"File not found, skipping delete: {file_path}")
                    # Decide if you still want to delete DB record if file is missing
                    # deleted_file = True # Or set to True to allow DB deletion
            except OSError as e:
                print(f"Error deleting file {file_path}: {e}")
                flash(f'Error deleting the physical file: {e}. Please contact support.', 'danger')
                # Optionally stop here if file deletion fails critically
                # return redirect(url_for('patient_dashboard'))

        # 2. Delete the record from MongoDB
        # Only proceed if file was deleted or if file was already missing (optional)
        # Modify condition based on desired behavior if file missing/deletion fails
        if deleted_file or not file_path: # Delete DB record if file deleted OR path was missing
            result = pdf_storage.delete_one({'_id': record_oid})
            if result.deleted_count == 1:
                flash(f'Record {filename or record_id} deleted successfully.', 'success')
            else:
                flash('Error deleting record from database.', 'danger')
        else:
             # Case where file existed but couldn't be deleted
             flash('Record kept in database because the associated file could not be deleted.', 'warning')

    except InvalidId:
         flash('Invalid record ID format.', 'danger')
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'danger')
        print(f"Error in delete_record: {e}")

    return redirect(url_for('patient_dashboard'))

# --- Simulated ZKP Allergy Verification Route ---
@app.route('/verify_allergy_zkp', methods=['POST'])
@login_required
def verify_allergy_zkp():
    # Only doctors should perform this check in this context
    if session.get('user_type') != 'doctor':
        flash('Only doctors can perform allergy verification.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        doctor_id_obj = ObjectId(session['user_id'])
        patient_id_str = request.form.get('patient_id')
        medication_query = request.form.get('medication_query', '').strip()

        if not patient_id_str or not medication_query:
            flash('Missing patient selection or medication query.', 'danger')
            return redirect(url_for('doctor_dashboard'))
            
        patient_id_obj = ObjectId(patient_id_str)

        # 1. Verify Doctor's Access to Patient
        doctor = doctors.find_one({'_id': doctor_id_obj}, {'metamask_address': 1})
        patient = patients.find_one({'_id': patient_id_obj}, {'metamask_address': 1, 'name': 1, 'allergies': 1})

        if not doctor or 'metamask_address' not in doctor or not patient or 'metamask_address' not in patient:
            flash('Could not find doctor or patient information for verification.', 'danger')
            return redirect(url_for('doctor_dashboard'))

        doctor_address_checksum = web3.to_checksum_address(doctor['metamask_address'])
        patient_address_checksum = web3.to_checksum_address(patient['metamask_address'])
        patient_name = patient.get('name', 'Unknown Patient')

        has_access = contract.functions.checkAccess(
            patient_address_checksum,
            doctor_address_checksum
        ).call()

        if not has_access:
            flash(f'You do not have access to verify data for patient {patient_name}.', 'danger')
            return redirect(url_for('doctor_dashboard'))

        # 2. Perform the "Proof" Generation (Simulation)
        allergies_list = patient.get('allergies', [])
        # Case-insensitive check
        is_allergic = any(medication_query.lower() == allergy.lower() for allergy in allergies_list)
        
        # 3. Create Mock Proof Object (Normally done by prover/patient system)
        mock_proof = {
            'query': medication_query,
            'result': is_allergic,
            'timestamp': datetime.now().isoformat(),
            'mock_proof_data': f"zkp_simulated_proof_{base64.b64encode(os.urandom(16)).decode()}",
            'verifier_address': doctor_address_checksum,
            'patient_address': patient_address_checksum
        }
        print(f"Simulated ZKP Generated: {mock_proof}")

        # 4. "Verification" (Simulated) - In reality, would verify mock_proof_data
        # Here we just trust the generated result for the simulation
        verification_passed = True # Assume verification works
        
        # 5. Flash Result
        if verification_passed:
            result_text = f"Patient {patient_name} IS allergic to '{medication_query}'" if mock_proof['result'] else f"Patient {patient_name} is NOT allergic to '{medication_query}'"
            # Use specific category for filtering in the template
            flash(result_text, 'zkp_result') 
        else:
            flash(f'Simulated ZKP verification failed for {medication_query}. Result unreliable.', 'danger')

    except InvalidId:
        flash('Invalid patient ID format.', 'danger')
    except ValueError as checksum_err:
         flash(f"Invalid address format encountered during verification: {checksum_err}", 'danger')
    except Exception as e:
        flash(f'An error occurred during allergy verification: {e}', 'danger')
        print(f"Error in verify_allergy_zkp: {e}")

    return redirect(url_for('doctor_dashboard'))

@app.route('/view_record/<record_id>')
@login_required
@patient_required
def view_record(record_id):
    try:
        record_oid = ObjectId(record_id)
        patient_id = ObjectId(session['user_id'])

        # Find the record in MongoDB
        record = pdf_storage.find_one({'_id': record_oid})

        if not record:
            flash('Record not found.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Security Check: Ensure the logged-in patient owns this record
        if record.get('patient_id') != patient_id:
            flash('Unauthorized: You do not own this record.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Fetch patient's private key
        key_data = encryption_keys.find_one({'patient_id': patient_id})
        if not key_data or 'private_key' not in key_data:
            flash('Your private key could not be found. Cannot decrypt record.', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        private_key_pem = key_data['private_key']
        encrypted_text = record.get('encrypted_text')
        filename = record.get('filename', 'Unknown File')

        if not encrypted_text:
            flash('No encrypted content found for this record.', 'warning')
            # Render template with message instead of error? 
            decrypted_content = "[No encrypted content available for this record]"
        else:
            # Decrypt the content
            try:
                decrypted_content = decrypt_data(encrypted_text, private_key_pem)
            except Exception as decrypt_error:
                print(f"Error decrypting record {record_id}: {decrypt_error}")
                flash(f'Failed to decrypt record content: {decrypt_error}', 'danger')
                decrypted_content = "[Error decrypting content]"

        # Render a template to display the decrypted content
        return render_template('view_record.html', 
                               filename=filename, 
                               content=decrypted_content)

    except InvalidId:
         flash('Invalid record ID format.', 'danger')
         return redirect(url_for('patient_dashboard'))
    except Exception as e:
        flash(f'An unexpected error occurred while viewing the record: {e}', 'danger')
        print(f"Error in view_record: {e}")
        return redirect(url_for('patient_dashboard'))

@app.route('/share_record/<record_id>', methods=['POST'])
@login_required
@patient_required
def share_record(record_id):
    try:
        record_oid = ObjectId(record_id)
        patient_id = ObjectId(session['user_id'])
        share_with_prefixed_id = request.form.get('share_with_id')

        if not share_with_prefixed_id:
            flash('No provider selected to share with.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Find the record to ensure it exists and patient owns it
        record = pdf_storage.find_one({'_id': record_oid, 'patient_id': patient_id})
        if not record:
            flash('Record not found or you do not own this record.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Parse the prefixed ID (e.g., "doc_123..." or "hosp_456...")
        parts = share_with_prefixed_id.split('_', 1)
        if len(parts) != 2 or parts[0] not in ['doc', 'hosp']:
             flash('Invalid provider selection format.', 'danger')
             return redirect(url_for('patient_dashboard'))
             
        provider_type = parts[0] # 'doc' or 'hosp'
        provider_id_str = parts[1]

        # Here you might want to add an extra check to ensure the provider_id_str 
        # corresponds to an actual doctor/hospital in the respective collection, 
        # but for simplicity, we'll proceed assuming valid IDs are passed from the dropdown.

        # Update the record in MongoDB to add the provider ID to the shared_with list
        # Using $addToSet ensures the ID isn't added if it already exists
        result = pdf_storage.update_one(
            {'_id': record_oid}, 
            {'$addToSet': {'shared_with': provider_id_str}}
        )

        if result.modified_count > 0 or result.matched_count > 0:
            # Need to fetch provider name for the message
            provider_name = "Selected Provider"
            try:
                if provider_type == 'doc':
                    p_info = doctors.find_one({'_id': ObjectId(provider_id_str)}, {'name': 1})
                    if p_info: provider_name = f"Dr. {p_info.get('name', provider_id_str)}"
                elif provider_type == 'hosp':
                    p_info = hospitals.find_one({'_id': ObjectId(provider_id_str)}, {'name': 1})
                    if p_info: provider_name = p_info.get('name', provider_id_str)
            except Exception as name_fetch_err:
                print(f"Error fetching provider name for flash message: {name_fetch_err}")
                
            flash(f'Record {record.get("filename", record_id)} shared successfully with {provider_name}.', 'success')
        else:
            # This might happen if the record wasn't found again, though unlikely after first check
            flash('Failed to update record sharing status.', 'danger')

    except InvalidId:
         flash('Invalid record or provider ID format.', 'danger')
    except Exception as e:
        flash(f'An unexpected error occurred during sharing: {e}', 'danger')
        print(f"Error in share_record: {e}")

    return redirect(url_for('patient_dashboard'))

@app.route('/setup_emergency_pin', methods=['POST'])
@login_required
@patient_required
def setup_emergency_pin():
    try:
        patient_id = session['user_id']
        emergency_pin = request.form.get('emergency_pin')
        
        # Validate PIN format
        if not emergency_pin or not emergency_pin.isdigit() or len(emergency_pin) < 4 or len(emergency_pin) > 6:
            flash('Invalid PIN format. Please enter 4-6 digits.', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        # Store PIN hash in database (in production, use proper hashing)
        patients.update_one(
            {'_id': ObjectId(patient_id)},
            {'$set': {'emergency_pin': emergency_pin}}
        )
        
        flash('Emergency PIN set successfully', 'success')
        return redirect(url_for('patient_dashboard'))
        
    except Exception as e:
        flash(f'Error setting emergency PIN: {str(e)}', 'danger')
        return redirect(url_for('patient_dashboard'))

@app.route('/emergency_access', methods=['GET', 'POST'])
def emergency_access():
    if request.method == 'POST':
        try:
            patient_name = request.form.get('patient_name')
            emergency_pin = request.form.get('emergency_pin')
            
            if not patient_name or not emergency_pin:
                flash('Please provide both patient name and emergency PIN', 'danger')
                return render_template('emergency_access.html') # Show form again on error
                
            # Get patient from database by name
            patient = patients.find_one({'name': patient_name})
            if not patient:
                flash('Patient not found', 'danger')
                return render_template('emergency_access.html') # Show form again on error
                
            # Verify emergency PIN
            if patient.get('emergency_pin') != emergency_pin:
                # Log failed attempt using patient name
                emergency_logs.insert_one({
                    'patient_name': patient_name, # Using name instead of ID
                    'timestamp': datetime.now(),
                    'ip_address': request.remote_addr,
                    'user_agent': request.user_agent.string,
                    'status': 'failed',
                    'reason': 'invalid_pin'
                })
                flash('Invalid emergency PIN', 'danger')
                return render_template('emergency_access.html') # Show form again on error
                
            # Get critical medical information
            critical_info = {
                'name': patient.get('name'),
                'blood_group': patient.get('blood_group'),
                'allergies': patient.get('allergies', []),
                'emergency_contact': patient.get('emergency_contact'),
                'medical_conditions': patient.get('medical_conditions', [])
            }
            
            # Log successful emergency access using patient name
            emergency_logs.insert_one({
                'patient_name': patient_name, # Using name instead of ID
                'timestamp': datetime.now(),
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string,
                'status': 'success',
                'accessed_info': list(critical_info.keys())
            })
            
            # Render the emergency info page on success
            return render_template('emergency_info.html', 
                               patient=critical_info,
                               timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                               
        except Exception as e:
            flash(f'Error accessing emergency information: {str(e)}', 'danger')
            return render_template('emergency_access.html') # Show form again on error
            
    # For GET requests, just render the emergency access form page
    return render_template('emergency_access.html')

if __name__ == '__main__':
    app.run(debug=True)