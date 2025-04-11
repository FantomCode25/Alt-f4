# app.py

# Monkeypatch for Python 3.12 compatibility with older packages
import sys
if sys.version_info >= (3, 12):
    # Add compatibility for inspect.getargspec which was removed in Python 3.12
    import inspect
    try:
        from inspect import getargspec
    except ImportError:
        # If getargspec is not available, provide our own implementation
        from inspect_compat import getargspec
        # Monkeypatch the inspect module
        inspect.getargspec = getargspec

from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from functools import wraps
import json
import os
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Try to import Web3 for blockchain functionality
try:
    from web3 import Web3
    web3_available = True
except ImportError:
    web3_available = False

# Connect to MongoDB
try:
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=2000)
    client.server_info()  # Will throw an exception if connection fails
    db = client['healthcare_db']
    hospitals = db['hospitals']
    doctors = db['doctors']
    patients = db['patients']
    mongodb_available = True
    print("MongoDB connection successful")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    # Create dummy collections for demo/testing
    mongodb_available = False
    class DummyCollection:
        def __init__(self):
            self.data = []
        def insert_one(self, data):
            data['_id'] = len(self.data) + 1
            self.data.append(data)
            return type('obj', (object,), {'inserted_id': data['_id']})
        def find_one(self, query):
            for item in self.data:
                match = True
                for k, v in query.items():
                    if k not in item or item[k] != v:
                        match = False
                        break
                if match:
                    return item
            return None
        def find(self, query=None):
            if query is None:
                return self.data
            results = []
            for item in self.data:
                match = True
                for k, v in query.items():
                    if k not in item or item[k] != v:
                        match = False
                        break
                if match:
                    results.append(item)
            return results
    
    hospitals = DummyCollection()
    doctors = DummyCollection()
    patients = DummyCollection()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_type = request.form['user_type']
        email = request.form['email']
        password = request.form['password']
        
        if user_type == 'hospital':
            user = hospitals.find_one({'email': email, 'password': password})
        elif user_type == 'doctor':
            user = doctors.find_one({'email': email, 'password': password})
        else:
            user = patients.find_one({'email': email, 'password': password})
        
        if user:
            session['user_id'] = str(user['_id'])
            session['user_type'] = user_type
            session['name'] = user['name']
            flash('Login successful', 'success')
            return redirect(url_for('patients_list'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/register_hospital', methods=['GET', 'POST'])
def register_hospital():
    if request.method == 'POST':
        hospital_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'date_registered': datetime.now()
        }
        
        # Check if hospital already exists
        if mongodb_available and hospitals.find_one({'email': hospital_data['email']}):
            flash('Hospital already registered with this email', 'danger')
            return redirect(url_for('register_hospital'))
        
        # Store in MongoDB or dummy collection
        try:
            hospitals.insert_one(hospital_data)
            flash('Hospital registered successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('register_hospital'))
    
    return render_template('register_hospital.html')

@app.route('/register_doctor', methods=['GET', 'POST'])
@login_required
def register_doctor():
    if session['user_type'] != 'hospital':
        flash('Only hospitals can register doctors', 'danger')
        return redirect(url_for('patients_list'))
    
    if request.method == 'POST':
        doctor_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'specialization': request.form['specialization'],
            'hospital_id': session['user_id'],
            'date_registered': datetime.now()
        }
        
        # Check if doctor already exists
        if mongodb_available and doctors.find_one({'email': doctor_data['email']}):
            flash('Doctor already registered with this email', 'danger')
            return redirect(url_for('register_doctor'))
        
        # Store in MongoDB or dummy collection
        try:
            doctors.insert_one(doctor_data)
            flash('Doctor registered successfully', 'success')
            return redirect(url_for('patients_list'))
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('register_doctor'))
    
    return render_template('register_doctor.html')

@app.route('/register_patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        patient_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'password': request.form['password'],
            'date_of_birth': request.form['date_of_birth'],
            'blood_group': request.form['blood_group'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'emergency_contact': request.form['emergency_contact'],
            'date_registered': datetime.now()
        }
        
        # Check if patient already exists
        if mongodb_available and patients.find_one({'email': patient_data['email']}):
            flash('Patient already registered with this email', 'danger')
            return redirect(url_for('register_patient'))
        
        # Store in MongoDB or dummy collection
        try:
            patients.insert_one(patient_data)
            flash('Patient registered successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('register_patient'))
    
    return render_template('register_patient.html')

@app.route('/patients')
@login_required
def patients_list():
    # Get all patients
    if mongodb_available:
        all_patients = list(patients.find())
    else:
        all_patients = patients.data
    
    return render_template('patients_list.html', patients=all_patients)

@app.route('/patient_details/<patient_id>')
@login_required
def patient_details(patient_id):
    # Find the patient by ID
    try:
        if mongodb_available:
            from bson.objectid import ObjectId
            try:
                patient_id = ObjectId(patient_id)
            except:
                pass
        
        patient = patients.find_one({'_id': patient_id})
        
        if not patient:
            flash('Patient not found', 'danger')
            return redirect(url_for('patients_list'))
        
        return render_template('patient_details.html', patient=patient)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('patients_list'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/blockchain_data')
@login_required
def blockchain_data():
    """
    Route to display blockchain data - simplified to avoid Web3 errors
    """
    try:
        if not web3_available:
            flash('Web3 library not available. Blockchain features are disabled.', 'warning')
            return redirect(url_for('patients_list'))
            
        # Mock data since we're moving away from blockchain functionality
        contract_info = {
            'address': '0x0000000000000000000000000000000000000000',
            'network': 'Not connected',
            'block_number': 0,
            'total_hospitals': 0
        }
        
        transactions = []
        events = []
        
        return render_template('blockchain_data.html', 
                              contract_info=contract_info,
                              transactions=transactions,
                              events=events)
    except Exception as e:
        flash(f'Error fetching blockchain data: {str(e)}', 'danger')
        return redirect(url_for('patients_list'))

if __name__ == '__main__':
    app.run(debug=True)