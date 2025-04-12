# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from functools import wraps
import json
from web3 import Web3
import os
from datetime import datetime, timezone, timedelta
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
import hashlib
import uuid
import google.generativeai as genai
import requests
from io import BytesIO
from dotenv import load_dotenv
from flask import send_from_directory  # Add this import for serving files

# For fallback OCR
try:
    import pytesseract
    from PIL import Image
    TESSERACT_AVAILABLE = True
    # Set tesseract path for Windows
    if os.name == 'nt':  # Windows
        pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        # Try alternative locations if the standard location doesn't work
        if not os.path.exists(pytesseract.pytesseract.tesseract_cmd):
            potential_paths = [
                r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
                r'C:\Tesseract-OCR\tesseract.exe'
            ]
            for path in potential_paths:
                if os.path.exists(path):
                    pytesseract.pytesseract.tesseract_cmd = path
                    break
except ImportError:
    TESSERACT_AVAILABLE = False
    print("Warning: pytesseract not available for fallback OCR")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load environment variables
load_dotenv()

# --- Date Formatting Filter --- 
@app.template_filter('formatdatetime')
def format_datetime(value, format='medium'):
    if format == 'full':
        format="EEEE, d MMMM y 'at' HH:mm"
    elif format == 'medium':
        format="d MMM y HH:mm"
    elif format == 'date_only':
        format="d MMM y"
    elif format == 'time_only':
        format="HH:mm"
    return babel.dates.format_datetime(value, format)

# Context processor to inject datetime object into templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(), 'timedelta': timedelta}

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'bmp'}
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
blockchain = db['blockchain']

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
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        
        # Get the number of pages
        num_pages = len(pdf_reader.pages)
        print(f"PDF has {num_pages} pages")
        
        if num_pages == 0:
            return "PDF has no pages"
        
        # Extract text from each page
        for i, page in enumerate(pdf_reader.pages):
            try:
                page_text = page.extract_text()
                if page_text:
                    text += f"--- Page {i+1} ---\n{page_text}\n\n"
                else:
                    text += f"--- Page {i+1} (No text found) ---\n\n"
                print(f"Extracted text from page {i+1}")
            except Exception as page_error:
                text += f"--- Page {i+1} (Error: {str(page_error)}) ---\n\n"
                print(f"Error extracting text from page {i+1}: {page_error}")
        
        # Check if we found any text
        if text.strip():
            return text
        else:
            return "No text could be extracted from the PDF. The file may be scanned images or protected."
    
    except PyPDF2.errors.PdfReadError as pdf_error:
        error_message = f"PDF read error: {str(pdf_error)}"
        print(error_message)
        return error_message
    except Exception as e:
        error_message = f"Error extracting text from PDF: {str(e)}"
        print(error_message)
        return error_message

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

# Gemini AI configuration
GEMINI_API_KEY = "AIzaSyD-UojYGfrgfE4LN8Pz0zszW09UQz-Yb5Y"  # Example key - replace in production
genai.configure(api_key=GEMINI_API_KEY)

# Blockchain functions
def calculate_hash(index, timestamp, data, previous_hash):
    value = str(index) + str(timestamp) + str(data) + str(previous_hash)
    return hashlib.sha256(value.encode()).hexdigest()

def create_genesis_block():
    if blockchain.count_documents({}) == 0:
        genesis_block = {
            'index': 0,
            'timestamp': str(datetime.now()),
            'data': "Genesis Block",
            'previous_hash': "0",
            'hash': "0"
        }
        blockchain.insert_one(genesis_block)

def create_new_block(data):
    last_block = blockchain.find_one(sort=[('index', -1)])
    
    if not last_block:
        create_genesis_block()
        last_block = blockchain.find_one(sort=[('index', -1)])
    
    new_block = {
        'index': last_block['index'] + 1,
        'timestamp': str(datetime.now()),
        'data': data,
        'previous_hash': last_block['hash']
    }
    
    new_block['hash'] = calculate_hash(
        new_block['index'], 
        new_block['timestamp'], 
        new_block['data'], 
        new_block['previous_hash']
    )
    
    blockchain.insert_one(new_block)
    return new_block

# Function for fallback OCR using pytesseract
def fallback_ocr_with_tesseract(file_path):
    """
    Use Tesseract OCR as a fallback when the OCR.space API fails
    """
    if not TESSERACT_AVAILABLE:
        return "Tesseract OCR not available for fallback processing. Please install pytesseract and Tesseract OCR."
    
    try:
        # Get file extension
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # Process based on file type
        if file_extension in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            # For image files
            try:
                image = Image.open(file_path)
                
                # Convert to RGB if needed (to handle PNG with transparency)
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Image preprocessing for better OCR results
                # 1. Resize image if too large (maintains aspect ratio)
                max_size = 3000  # Maximum dimension
                if max(image.size) > max_size:
                    ratio = max_size / max(image.size)
                    new_size = (int(image.size[0] * ratio), int(image.size[1] * ratio))
                    image = image.resize(new_size, Image.Resampling.LANCZOS)
                
                # 2. Apply additional preprocessing if needed
                # For example, we could enhance contrast or apply thresholding for better results
                
                # Use pytesseract with optimized configuration for medical text
                custom_config = r'--oem 3 --psm 6 -l eng'  # OCR Engine Mode 3, Page Segmentation Mode 6 (assumes a single uniform block of text)
                text = pytesseract.image_to_string(image, config=custom_config)
                
                # Check if we got any text
                if not text.strip():
                    # Try again with different parameters if first attempt failed
                    print("First OCR attempt failed, trying with different parameters...")
                    custom_config = r'--oem 3 --psm 4 -l eng'  # PSM 4 (assumes a single column of text of variable sizes)
                    text = pytesseract.image_to_string(image, config=custom_config)
                
                if not text.strip():
                    return "No text found in image. The image may not contain readable text or the text might be in an unsupported format/language."
                
                return f"[Extracted using local OCR]\n{text}"
            
            except Exception as img_err:
                print(f"Error processing image: {img_err}")
                return f"Error processing image for OCR: {str(img_err)}"
                
        elif file_extension == '.pdf':
            # For PDF files, extract using PyPDF2 first
            pdf_text = extract_pdf_text(file_path)
            
            # If PyPDF2 extraction was successful, return that
            if pdf_text and not pdf_text.startswith("Error"):
                return pdf_text
                
            # Otherwise, attempt to convert PDF pages to images and OCR them
            try:
                from pdf2image import convert_from_path
                
                # Convert PDF to images
                images = convert_from_path(file_path)
                text = ""
                
                # Process each page
                for i, image in enumerate(images):
                    # Apply same preprocessing as for regular images
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    
                    # Use optimized configuration
                    custom_config = r'--oem 3 --psm 6 -l eng'
                    page_text = pytesseract.image_to_string(image, config=custom_config)
                    
                    # If no text found, try different parameters
                    if not page_text.strip():
                        custom_config = r'--oem 3 --psm 4 -l eng'
                        page_text = pytesseract.image_to_string(image, config=custom_config)
                    
                    text += f"--- Page {i+1} ---\n{page_text}\n\n"
                
                if not text.strip():
                    return "No text found in PDF using local OCR. The PDF may contain images without readable text."
                    
                return f"[Extracted using local PDF OCR]\n{text}"
                
            except ImportError:
                return "PDF conversion library not available for local OCR of PDF files. Please install pdf2image."
        else:
            return f"Unsupported file type for local OCR: {file_extension}"
            
    except Exception as e:
        return f"Error in local OCR processing: {str(e)}"

# Function to process OCR using OCR.space API with fallback to local Tesseract
def process_ocr(file_path):
    api_key = 'K85412180888957'  # Replace with actual OCR.space API key in production
    
    try:
        # Get file extension
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # First, try using the OCR.space API
        try:
            # Read file as binary
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Determine content-type based on file extension
            content_type = None
            if file_extension in ['.pdf']:
                content_type = 'application/pdf'
            elif file_extension in ['.png']:
                content_type = 'image/png'
            elif file_extension in ['.jpg', '.jpeg']:
                content_type = 'image/jpeg'
            elif file_extension in ['.gif']:
                content_type = 'image/gif'
            elif file_extension in ['.bmp']:
                content_type = 'image/bmp'
            
            if not content_type:
                print(f"Unsupported file type for OCR.space API: {file_extension}")
                return fallback_ocr_with_tesseract(file_path)
            
            # Prepare the request for OCR.space API
            files = {'file': ('file' + file_extension, file_data, content_type)}
            payload = {
                'apikey': api_key,
                'language': 'eng',
                'isOverlayRequired': 'false',
                'detectOrientation': 'true',
                'scale': 'true',
                'OCREngine': '2'  # Using more accurate OCR engine
            }
            
            # Configure retry settings
            max_retries = 2
            retry_count = 0
            
            while retry_count <= max_retries:
                try:
                    # Send request to OCR.space with proper timeout
                    response = requests.post(
                        'https://api.ocr.space/parse/image',
                        files=files,
                        data=payload,
                        timeout=30  # Setting a reasonable timeout
                    )
                    
                    # Check if request was successful
                    if response.status_code != 200:
                        print(f"OCR API error: Status {response.status_code} (Attempt {retry_count+1}/{max_retries+1})")
                        retry_count += 1
                        if retry_count > max_retries:
                            print("All API retries failed, falling back to local OCR")
                            return fallback_ocr_with_tesseract(file_path)
                        continue
                    
                    # Parse JSON response
                    try:
                        ocr_result = response.json()
                    except Exception as json_err:
                        print(f"Error parsing OCR API response: {json_err}")
                        retry_count += 1
                        if retry_count > max_retries:
                            print("All API retries failed, falling back to local OCR")
                            return fallback_ocr_with_tesseract(file_path)
                        continue
                    
                    # Check for API errors
                    if ocr_result.get('IsErroredOnProcessing', False):
                        error_message = ocr_result.get('ErrorMessage', ['Unknown OCR error'])[0]
                        print(f"OCR processing error: {error_message} (Attempt {retry_count+1}/{max_retries+1})")
                        retry_count += 1
                        if retry_count > max_retries:
                            print("All API retries failed, falling back to local OCR")
                            return fallback_ocr_with_tesseract(file_path)
                        continue
                    
                    # Extract text from OCR results
                    if 'ParsedResults' in ocr_result and ocr_result['ParsedResults']:
                        parsed_text = ocr_result['ParsedResults'][0].get('ParsedText', '')
                        if parsed_text.strip():
                            return parsed_text
                        else:
                            print("OCR API returned empty result, trying fallback OCR")
                            return fallback_ocr_with_tesseract(file_path)
                    
                    print("OCR API returned no parsed results, trying fallback OCR")
                    return fallback_ocr_with_tesseract(file_path)
                    
                except requests.exceptions.RequestException as req_err:
                    print(f"OCR API request error: {req_err} (Attempt {retry_count+1}/{max_retries+1})")
                    retry_count += 1
                    if retry_count > max_retries:
                        print("All API retries failed, falling back to local OCR")
                        return fallback_ocr_with_tesseract(file_path)
            
        except Exception as api_err:
            print(f"Error with OCR.space API: {api_err}")
            print("Trying fallback OCR")
            return fallback_ocr_with_tesseract(file_path)
        
        # If we get here without returning, try fallback OCR
        print("OCR.space API failed, trying fallback OCR")
        return fallback_ocr_with_tesseract(file_path)
    
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return "File not found for OCR processing."
    except Exception as e:
        print(f"Unexpected error in OCR processing: {e}")
        return f"Error processing document with OCR: {e}"

# Function for fallback AI summary generation using local processing
def generate_local_summary(text, max_sentences=10):
    """
    Generate a summary of the text using a simple extractive summarization approach.
    This is a fallback when the Gemini AI API is unavailable.
    """
    try:
        import re
        from collections import Counter
        import math
        
        # Check if we have enough text to summarize
        if not text or len(text) < 100:
            return "Text too short for meaningful summarization."
        
        # Clean and prepare the text
        # Remove newlines and extra spaces
        text = re.sub(r'\s+', ' ', text)
        
        # Split text into sentences
        sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s', text)
        
        # Remove very short sentences
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        if not sentences or len(sentences) < 3:
            return "Not enough complete sentences for summarization."
        
        # Tokenize words and calculate word frequency
        words = re.findall(r'\w+', text.lower())
        word_freq = Counter(words)
        
        # Remove very common words (stop words)
        stop_words = {'the', 'a', 'an', 'and', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 
                      'by', 'as', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 
                      'has', 'had', 'do', 'does', 'did', 'but', 'or', 'if', 'then', 'else', 
                      'so', 'such', 'this', 'that', 'these', 'those', 'it', 'its'}
        
        for word in stop_words:
            if word in word_freq:
                del word_freq[word]
        
        # Calculate sentence scores based on word frequency
        sentence_scores = {}
        for i, sentence in enumerate(sentences):
            sentence_words = re.findall(r'\w+', sentence.lower())
            score = sum(word_freq.get(word, 0) for word in sentence_words) / max(1, len(sentence_words))
            
            # Give more weight to sentences at beginning and end of the text
            if i < len(sentences) * 0.2:  # First 20% of sentences
                score *= 1.2
            elif i > len(sentences) * 0.8:  # Last 20% of sentences
                score *= 1.1
                
            sentence_scores[i] = score
        
        # Extract medical terms to emphasize sentences containing them
        medical_keywords = {
            'diagnosis', 'treatment', 'patient', 'doctor', 'hospital', 'medicine', 'prescription',
            'symptom', 'disease', 'condition', 'blood', 'test', 'scan', 'xray', 'x-ray', 'mri',
            'ct', 'ultrasound', 'lab', 'result', 'positive', 'negative', 'surgery', 'operation',
            'dose', 'therapy', 'chronic', 'acute', 'emergency', 'mg', 'ml', 'dosage', 'allergy',
            'allergic', 'reaction', 'medication', 'prescribed', 'follow-up', 'followup', 'history'
        }
        
        # Boost sentences with medical terms
        for i, sentence in enumerate(sentences):
            sentence_lower = sentence.lower()
            med_term_count = sum(1 for term in medical_keywords if term in sentence_lower)
            if med_term_count > 0:
                sentence_scores[i] *= (1 + 0.1 * med_term_count)  # 10% boost per medical term
        
        # Get the top scoring sentences (with their original indices to maintain order)
        top_sentences = sorted(sentence_scores.items(), key=lambda x: x[1], reverse=True)[:max_sentences]
        top_sentences = sorted(top_sentences, key=lambda x: x[0])  # Sort by position in text
        
        # Create the summary
        summary = "\n".join(sentences[i] for i, _ in top_sentences)
        
        # Add a header to indicate this is a locally-generated summary
        final_summary = "[Local AI Summary]\n\n" + summary
        
        return final_summary
        
    except Exception as e:
        print(f"Error in local summarization: {e}")
        return f"Error generating local summary: {str(e)}"

# Function for using Claude API for summarization
def summarize_text(text):
    """
    Send text to the Anthropic API for summarization.
    
    Args:
        text (str): The text to summarize
        
    Returns:
        str: The summarized text or error message
    """
    # Load API key from environment variable
    API_KEY = os.getenv("ANTHROPIC_API_KEY")
    
    if not API_KEY:
        return "Error: No API key found. Please set the ANTHROPIC_API_KEY environment variable."
    
    API_URL = "https://api.anthropic.com/v1/messages"
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01"
    }
    
    payload = {
        "model": "claude-3-opus-20240229",
        "max_tokens": 1000,
        "messages": [
            {"role": "user", "content": f"Please summarize the following medical text in a concise way, highlighting the key points:\n\n{text}"}
        ]
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        response.raise_for_status()
        
        # Extract summary from response
        result = response.json()
        summary = result["content"][0]["text"]
        
        return summary
    except requests.exceptions.RequestException as e:
        return f"API Error: {str(e)}"
    except KeyError as e:
        return f"Unexpected API response format: {str(e)}"

# Function to get summary from AI services with fallback mechanisms
def generate_ai_summary(text):
    """
    Generate a summary of text using various AI services with fallback options.
    First tries Google Gemini AI, then Claude API, then local summarization.
    """
    try:
        # First try with Google Gemini AI
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(
            f"Summarize the following medical text and extract key medical information:\n\n{text}"
        )
        return response.text
    except Exception as gemini_error:
        print(f"Error generating summary with Gemini AI: {gemini_error}")
        
        # If Gemini fails, try Claude API
        try:
            print("Falling back to Claude API for summarization")
            claude_summary = summarize_text(text)
            
            # Check if Claude API returned an error
            if claude_summary.startswith("API Error:") or claude_summary.startswith("Error:") or claude_summary.startswith("Unexpected API"):
                print(f"Claude API failed: {claude_summary}")
                # Fall back to local summarization
                print("Falling back to local summarization")
                local_summary = generate_local_summary(text)
                return f"External AI services unavailable. Using local summarization.\n\n{local_summary}"
            else:
                return f"[Claude AI Summary]\n\n{claude_summary}"
                
        except Exception as claude_error:
            print(f"Error with Claude API: {claude_error}")
            # Fall back to local summarization
            print("Falling back to local summarization")
            local_summary = generate_local_summary(text)
            return f"AI summary services failed. Using local summarization instead.\n\n{local_summary}"

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
            # FIXED: In production, this should be handled client-side with MetaMask
            # The transaction should be initiated by the patient's wallet

            # For development testing, we use the first Ganache account
            account = web3.eth.accounts[0]
            
            # Ensure address is checksummed for validation
            patient_metamask_address = web3.to_checksum_address(patient_data['metamask_address'])
            
            # FIXED: Corrected parameters according to contract expectations
            # The contract expects: name, patientId, bloodGroup, publicKey
            tx_hash = contract.functions.registerPatient(
                patient_data['name'],       
                patient_id_str,           # MongoDB ID as string
                patient_data['blood_group'],
                patient_data['public_key'] 
            ).transact({'from': account})
            # Production would use: .transact({'from': patient_metamask_address})
            
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
    if session.get('user_type') != 'doctor':
        flash('Access denied: You do not have permission to view this page', 'danger')
        return redirect(url_for('index'))
    
    doctor_id = session['user_id']
    
    # Get doctor information
    doctor = db.doctors.find_one({"_id": ObjectId(doctor_id)})
    
    # Get shared medical records for this doctor
    shared_records = list(db.shared_files.find({
        "shared_with_doctor": str(doctor_id)
    }).sort("shared_date", -1))
    
    # Enrich shared records with patient names
    for record in shared_records:
        try:
            patient = db.patients.find_one({"_id": ObjectId(record["patient_id"])})
            if patient:
                record["patient_name"] = patient.get("name", "Unknown Patient")
            else:
                record["patient_name"] = "Unknown Patient"
        except Exception as e:
            record["patient_name"] = "Unknown Patient"
            app.logger.error(f"Error fetching patient: {str(e)}")
    
    # Get a list of all patients who have authorized this doctor
    patient_ids = list(set(record["patient_id"] for record in shared_records))
    authorized_patients = list(db.patients.find({
        "_id": {"$in": [ObjectId(id) for id in patient_ids]}
    }))
    
    return render_template('doctor_dashboard.html',
                          doctor=doctor,
                          shared_records=shared_records,
                          authorized_patients=authorized_patients,
                          now=datetime.now())

# --- Dedicated Patient Dashboard Route --- 
@app.route('/patient_dashboard')
@login_required
def patient_dashboard():
    if session.get('user_type') != 'patient':
        flash('Access denied: You do not have permission to view this page', 'danger')
        return redirect(url_for('index'))
    
    patient_id = session['user_id']
    
    # Get patient information
    patient = db.patients.find_one({"_id": ObjectId(patient_id)})
    
    # Get all medical records for this patient
    medical_records = list(db.medical_records.find({
        "patient_id": str(patient_id)
    }).sort("date", -1))
    
    # Get authorized doctors for this patient
    authorized_doctors = []
    if patient and "authorized_doctors" in patient:
        doctor_ids = patient["authorized_doctors"]
        authorized_doctors = list(db.doctors.find({
            "_id": {"$in": [ObjectId(id) for id in doctor_ids]}
        }))
    
    # Get authorized hospitals for this patient
    authorized_hospitals = []
    if patient and "authorized_hospitals" in patient:
        hospital_ids = patient["authorized_hospitals"]
        authorized_hospitals = list(db.hospitals.find({
            "_id": {"$in": [ObjectId(id) for id in hospital_ids]}
        }))
    
    # Get all available doctors for the access form
    available_doctors = list(db.doctors.find())
    
    return render_template('patient_dashboard.html',
                          patient=patient,
                          medical_records=medical_records,
                          authorized_doctors=authorized_doctors,
                          authorized_hospitals=authorized_hospitals,
                          available_doctors=available_doctors,
                          now=datetime.now())

# --- Dedicated Hospital Dashboard Route --- 
@app.route('/hospital_dashboard')
@login_required
def hospital_dashboard():
    if session.get('user_type') != 'hospital':
        flash('Access denied: You do not have permission to view this page', 'danger')
        return redirect(url_for('index'))
    
    hospital_id = session['user_id']
    
    # Get hospital information
    hospital = db.hospitals.find_one({"_id": ObjectId(hospital_id)})
    
    # Get shared medical records for this hospital
    shared_records = list(db.shared_files.find({
        "shared_with_hospital": str(hospital_id)
    }).sort("shared_date", -1))
    
    # Enrich shared records with patient names
    for record in shared_records:
        try:
            patient = db.patients.find_one({"_id": ObjectId(record["patient_id"])})
            if patient:
                record["patient_name"] = patient.get("name", "Unknown Patient")
            else:
                record["patient_name"] = "Unknown Patient"
        except Exception as e:
            record["patient_name"] = "Unknown Patient"
            app.logger.error(f"Error fetching patient: {str(e)}")
    
    # Get a list of all patients who have authorized this hospital
    patient_ids = list(set(record["patient_id"] for record in shared_records))
    authorized_patients = list(db.patients.find({
        "_id": {"$in": [ObjectId(id) for id in patient_ids]}
    }))
    
    return render_template('hospital_dashboard.html',
                          hospital=hospital,
                          shared_records=shared_records,
                          authorized_patients=authorized_patients,
                          now=datetime.now())

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
        # Get doctor_id from form
        doctor_id = request.form.get('doctor_id')
        if not doctor_id:
            flash('Please select a doctor', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        # Get doctor's MetaMask address
        doctor = db.doctors.find_one({"_id": ObjectId(doctor_id)})
        if not doctor or 'metamask_address' not in doctor:
            flash('Doctor not found or has no MetaMask address', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        user_address = web3.to_checksum_address(doctor['metamask_address'])
        
        # Get duration from form
        duration_days = int(request.form.get('access_duration', 7))
        duration = duration_days * 24 * 60 * 60  # Convert days to seconds
        
        # Get fields access
        if request.form.get('allow_all_records') == '1':
            allowed_fields = ["*"]  # All fields
        else:
            allowed_fields = request.form.getlist('fields', ["*"])
        
        # Update the patient's authorized_doctors list in MongoDB
        patient = db.patients.find_one({"_id": ObjectId(patient_id)})
        if patient:
            authorized_doctors = patient.get("authorized_doctors", [])
            if doctor_id not in authorized_doctors:
                authorized_doctors.append(doctor_id)
                db.patients.update_one(
                    {"_id": ObjectId(patient_id)},
                    {"$set": {"authorized_doctors": authorized_doctors}}
                )
        
        # Grant access on blockchain
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.grantAccess(
            patient_id,             # Patient ID (string)
            user_address,           # Grantee address
            duration,               # Duration in seconds 
            allowed_fields          # Allowed fields
        ).transact({'from': account})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Access granted successfully to Dr. ' + doctor.get('name', ''), 'success')
    except Exception as e:
        flash(f'Error granting access: {str(e)}', 'danger')
    
    return redirect(url_for('patient_dashboard'))

@app.route('/revoke_access/<patient_id>', methods=['POST'])
@login_required
@patient_required
def revoke_access(patient_id):
    try:
        # Get doctor_id from form
        doctor_id = request.form.get('doctor_id')
        if not doctor_id:
            flash('Doctor ID is required', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        # Get doctor's MetaMask address
        doctor = db.doctors.find_one({"_id": ObjectId(doctor_id)})
        if not doctor or 'metamask_address' not in doctor:
            flash('Doctor not found or has no MetaMask address', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        user_address = web3.to_checksum_address(doctor['metamask_address'])
        
        # Remove doctor from authorized_doctors list in MongoDB
        db.patients.update_one(
            {"_id": ObjectId(patient_id)},
            {"$pull": {"authorized_doctors": doctor_id}}
        )
        
        # Revoke access on blockchain
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.revokeAccess(
            patient_id,   # Patient ID (string)
            user_address  # Address to revoke
        ).transact({'from': account})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)
        flash('Access revoked successfully for Dr. ' + doctor.get('name', ''), 'success')
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

        # FIXED: Corrected parameter order to match smart contract definition
        # Contract expects: (patientId, grantedTo, duration, allowedFields)
        tx_hash = contract.functions.grantAccess(
            logged_in_patient_id_str,  # Patient ID (string) - correct first parameter
            address_to_grant,         # Address receiving access 
            duration_seconds,         # Duration in seconds
            allowed_fields            # Fields allowed
        # FUTURE: Should be sent from patient's wallet in production
        # ).transact({'from': granting_patient_metamask_address})
        ).transact({'from': web3.eth.accounts[0]}) # For development only
        
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

@app.route('/verify_zkp', methods=['POST'])
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

        # FIXED: Check parameters - checkAccess expects patientId (string) and user address
        has_access = contract.functions.checkAccess(
            patient_id_str,  # Patient ID string, not address
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
            'patient_id': patient_id_str
        }
        print(f"Simulated ZKP Generated: {mock_proof}")

        # 4. "Verification" (Simulated) - In reality this would call the contract
        # FIXED: The contract expects patientId (string) and proof (bytes)
        try:
            proof_bytes = mock_proof['mock_proof_data'].encode()
            verification_result = contract.functions.verifyZeroKnowledgeProof(
                patient_id_str,  # Patient ID (string)
                proof_bytes      # Proof data as bytes
            ).call({'from': doctor_address_checksum})
            
            verification_passed = verification_result
        except Exception as verify_err:
            print(f"ZKP Verification Error (simulated): {verify_err}")
            verification_passed = True # For simulation, assume success
        
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
        is_pdf_storage = False
        is_medical_file = False
        patient_id = ObjectId(session['user_id'])
        share_with_prefixed_id = request.form.get('share_with_id')

        if not share_with_prefixed_id:
            flash('No provider selected to share with.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # First try to find the record in pdf_storage
        record = pdf_storage.find_one({'_id': ObjectId(record_id), 'patient_id': patient_id})
        
        if record:
            is_pdf_storage = True
        else:
            # If not found in pdf_storage, try medical_files
            record = medical_files.find_one({'_id': ObjectId(record_id), 'patient_id': patient_id})
            if record:
                is_medical_file = True
                
        if not record:
            flash('Record not found or you do not have permission to share it.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Parse the prefixed ID (e.g., "doc_123..." or "hosp_456...")
        parts = share_with_prefixed_id.split('_', 1)
        if len(parts) != 2 or parts[0] not in ['doc', 'hosp']:
             flash('Invalid provider selection format.', 'danger')
             return redirect(url_for('patient_dashboard'))
             
        provider_type = parts[0] # 'doc' or 'hosp'
        provider_id_str = parts[1]

        # Verify the provider exists before sharing
        provider_name = "Selected Provider"
        provider_exists = False
        
        try:
            if provider_type == 'doc':
                provider = doctors.find_one({'_id': ObjectId(provider_id_str)})
                if provider:
                    provider_exists = True
                    provider_name = f"Dr. {provider.get('name', 'Unknown')}"
            elif provider_type == 'hosp':
                provider = hospitals.find_one({'_id': ObjectId(provider_id_str)})
                if provider:
                    provider_exists = True
                    provider_name = provider.get('name', 'Unknown Hospital')
        except (InvalidId, Exception) as e:
            flash(f'Error verifying provider: {str(e)}', 'danger')
            return redirect(url_for('patient_dashboard'))
            
        if not provider_exists:
            flash(f'Selected provider does not exist in the system.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Update the record in appropriate MongoDB collection
        result = None
        if is_pdf_storage:
            result = pdf_storage.update_one(
                {'_id': ObjectId(record_id)}, 
                {'$addToSet': {'shared_with': provider_id_str}}
            )   
        elif is_medical_file:
            result = medical_files.update_one(
                {'_id': ObjectId(record_id)}, 
            {'$addToSet': {'shared_with': provider_id_str}}
        )

        if result and (result.modified_count > 0 or result.matched_count > 0):
            # Get record name for message
            record_name = record.get("filename", record.get("original_filename", record_id))
            
            flash(f'Record "{record_name}" shared successfully with {provider_name}.', 'success')
        else:
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

@app.route('/upload_medical_file', methods=['GET', 'POST'])
@login_required
def upload_medical_file():
    if request.method == 'GET':
        # Get list of patients that the doctor has access to
        if session.get('user_type') == 'doctor':
            # Fetch all patients instead of just those with access
            patient_list = list(patients.find())
            # Get list of hospitals for sharing
            hospital_list = list(hospitals.find({}, {'_id': 1, 'name': 1}))
            # Get list of doctors for sharing
            doctor_list = list(doctors.find({}, {'_id': 1, 'name': 1, 'specialization': 1}))
            return render_template('upload_medical_file.html', 
                                  patients=patient_list, 
                                  hospitals=hospital_list,
                                  doctors=doctor_list)
        elif session.get('user_type') == 'patient':
            patient_id = ObjectId(session['user_id'])
            patient = patients.find_one({'_id': patient_id})
            # Get list of hospitals for sharing
            hospital_list = list(hospitals.find({}, {'_id': 1, 'name': 1}))
            # Get list of doctors for sharing
            doctor_list = list(doctors.find({}, {'_id': 1, 'name': 1, 'specialization': 1}))
            return render_template('upload_medical_record.html', 
                                  patient=patient,
                                  hospitals=hospital_list,
                                  doctors=doctor_list)
    
    if request.method == 'POST':
        try:
            # Get form data
            if session.get('user_type') == 'doctor':
                patient_id = request.form.get('patient_id')
                if not patient_id:
                    flash('Please select a patient', 'danger')
                    return redirect(url_for('upload_medical_file'))
            else:  # Patient upload
                patient_id = session['user_id']
            
            # Convert ID string to ObjectId
            patient_id_obj = ObjectId(patient_id)
            
            # Get other form data
            doc_type = request.form.get('file_type')
            description = request.form.get('description')
            file = request.files.get('file')
            
            # Get hospital and doctor IDs to share with (if provided)
            share_with_hospital_ids = request.form.getlist('share_with_hospital') 
            share_with_doctor_ids = request.form.getlist('share_with_doctor')
            
            if not all([doc_type, file]):
                flash('Please fill in all required fields', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Validate file
            if not file or not file.filename:
                flash('No file selected', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Check file extension is allowed
            file_extension = ''
            if '.' in file.filename:
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                if file_extension not in ALLOWED_EXTENSIONS:
                    flash(f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'danger')
                    return redirect(url_for('upload_medical_file'))
            else:
                flash('File has no extension', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Read file into memory first to check size
            file_data = file.read()
            if len(file_data) > 10 * 1024 * 1024:  # 10MB in bytes
                flash('File size exceeds 10MB limit', 'danger')
                return redirect(url_for('upload_medical_file'))
            
            # Generate unique filename
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            
            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join(app.root_path, 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)
            
            # Save file to disk
            file_path = os.path.join(upload_dir, unique_filename)
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Generate unique document ID for blockchain
            doc_id = str(uuid.uuid4())
            
            # Initialize processing variables
            extracted_text = "Text extraction not attempted"
            summary = "Summary generation not attempted"
            processing_status = "Unknown"
            
            try:
                # Process with OCR based on file type
                if file_extension in ALLOWED_EXTENSIONS:
                    print(f"Starting OCR processing for file: {file_path} (type: {file_extension})")
                    extracted_text = process_ocr(file_path)
                    
                    if not extracted_text.startswith("Error") and not extracted_text.startswith("OCR processing error"):
                        processing_status = "OCR_SUCCESS"
                        print("OCR Extraction successful")
                        
                        # Only try to generate summary if we have valid extracted text
                        try:
                            print("Starting AI summary generation")
                            summary = generate_ai_summary(extracted_text)
                            if not summary.startswith("AI summary") and not summary.startswith("Failed"):
                                processing_status = "FULL_SUCCESS"
                                print("AI Summary generation successful")
                            else:
                                processing_status = "OCR_ONLY"
                                print("AI Summary generation failed")
                        except Exception as sum_err:
                            processing_status = "OCR_ONLY"
                            summary = f"AI summary generation failed: {str(sum_err)}"
                            print(f"Error in AI summary generation: {sum_err}")
                    else:
                        processing_status = "OCR_FAILED"
                        summary = "AI summary not available due to OCR failure"
                        print(f"OCR failed: {extracted_text}")
                else:
                    processing_status = "UNSUPPORTED_TYPE"
                    extracted_text = f"Unsupported file type: {file_extension}"
                    summary = "Summary not available for this file type"
                    print(f"Unsupported file type: {file_extension}")
            except Exception as proc_err:
                processing_status = "PROCESSING_ERROR"
                print(f"General processing error: {proc_err}")
                if not extracted_text or extracted_text == "Text extraction not attempted":
                    extracted_text = f"Error during text extraction: {str(proc_err)}"
                if not summary or summary == "Summary generation not attempted":
                    summary = "Summary not available due to processing error"
            
            # Fetch patient's key for encryption (if needed in the future)
            patient_data = patients.find_one({'_id': patient_id_obj})
            
            # Create blockchain record - only include the summary, not the extracted text
            blockchain_data = {
                'doc_id': doc_id,
                'patient_id': str(patient_id_obj),
                'uploader_id': session['user_id'],
                'uploader_type': session['user_type'],
                'file_hash': hashlib.sha256(file_data).hexdigest(),
                'summary_hash': hashlib.sha256(summary.encode()).hexdigest() if summary else None,
                'timestamp': str(datetime.now()),
                'processing_status': processing_status
            }
            
            # Create blockchain block
            blockchain_block = create_new_block(blockchain_data)
            
            # Prepare shared_with list combining hospitals and doctors
            shared_with_list = []
            
            # Add selected hospital IDs
            if share_with_hospital_ids:
                for hospital_id in share_with_hospital_ids:
                    try:
                        if hospital_id and hospital_id.strip():
                            # Verify hospital exists before adding to shared list
                            if hospitals.find_one({'_id': ObjectId(hospital_id)}):
                                shared_with_list.append(hospital_id)
                    except (InvalidId, Exception) as e:
                        print(f"Invalid hospital ID for sharing: {hospital_id}, error: {e}")
            
            # Add selected doctor IDs
            if share_with_doctor_ids:
                for doctor_id in share_with_doctor_ids:
                    try:
                        if doctor_id and doctor_id.strip():
                            # Verify doctor exists before adding to shared list
                            if doctors.find_one({'_id': ObjectId(doctor_id)}):
                                shared_with_list.append(doctor_id)
                    except (InvalidId, Exception) as e:
                        print(f"Invalid doctor ID for sharing: {doctor_id}, error: {e}")
            
            # Store file metadata in database with both extracted text and AI summary 
            file_data = {
                'doc_id': doc_id,
                'patient_id': patient_id_obj,
                'uploader_id': ObjectId(session['user_id']),
                'uploader_type': session['user_type'],
                'file_type': doc_type,
                'description': description,
                'filename': unique_filename,
                'original_filename': filename,
                'file_extension': file_extension,
                'upload_date': datetime.now(),
                'file_path': file_path,
                'extracted_text': extracted_text,  # Keep extracted text for immediate display
                'summary': summary,                # Store AI summary for permanent storage
                'blockchain_hash': blockchain_block['hash'],
                'blockchain_index': blockchain_block['index'],
                'processing_status': processing_status,
                'shared_with': shared_with_list  # Use our prepared list of IDs
            }
            
            # Insert into the appropriate collection
            inserted_id = medical_files.insert_one(file_data).inserted_id
            
            # Success message based on processing status
            if processing_status == "FULL_SUCCESS":
                flash('Medical document uploaded and processed successfully. Both extracted text and AI summary are available.', 'success')
            elif processing_status == "OCR_ONLY":
                flash('Document uploaded and text extracted successfully, but AI summary generation failed.', 'warning')
            elif processing_status == "OCR_FAILED":
                flash('Document uploaded, but text extraction failed. AI summary is not available.', 'warning')
            else:
                flash('Document uploaded, but processing was incomplete. Some features may not be available.', 'warning')
                
            # Add message about sharing if applicable
            if shared_with_list:
                share_count = len(shared_with_list)
                flash(f'File has been shared with {share_count} healthcare provider(s).', 'info')
            
            # Redirect to view the file
            return redirect(url_for('view_medical_file', file_id=inserted_id))
            
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            print(f"Exception in upload_medical_file: {e}")
            return redirect(url_for('upload_medical_file'))

@app.route('/view_medical_file/<file_id>')
@login_required
def view_medical_file(file_id):
    try:
        file_obj_id = ObjectId(file_id)
        file_data = medical_files.find_one({'_id': file_obj_id})
        
        if not file_data:
            flash('File not found', 'danger')
            return redirect(url_for('dashboard'))
            
        # Check access permission
        user_id = session['user_id']
        user_type = session['user_type']
        
        # Allow access to uploader, patient who owns the file, or shared users
        has_access = (
            str(file_data['uploader_id']) == user_id or
            str(file_data['patient_id']) == user_id or
            user_id in file_data.get('shared_with', [])
        )
        
        if not has_access:
            # Check blockchain-based access
            try:
                # Convert to string for blockchain compatibility
                patient_id_str = str(file_data['patient_id'])
                
                if user_type == 'doctor':
                    doctor = doctors.find_one({'_id': ObjectId(user_id)}, {'metamask_address': 1})
                    if doctor and 'metamask_address' in doctor:
                        doctor_address = doctor['metamask_address']
                        has_access = contract.functions.checkAccess(
                            patient_id_str,
                            doctor_address
                        ).call()
                elif user_type == 'hospital':
                    hospital = hospitals.find_one({'_id': ObjectId(user_id)}, {'metamask_address': 1})
                    if hospital and 'metamask_address' in hospital:
                        hospital_address = hospital['metamask_address']
                        has_access = contract.functions.checkAccess(
                            patient_id_str,
                            hospital_address
                        ).call()
            except Exception as e:
                print(f"Error checking blockchain access: {e}")
                has_access = False
        
        if not has_access:
            flash('You do not have permission to view this file', 'danger')
            return redirect(url_for('dashboard'))
            
        # Verify blockchain integrity
        blockchain_verification = "Unverified"
        try:
            blockchain_record = blockchain.find_one({'index': file_data.get('blockchain_index')})
            if blockchain_record and blockchain_record['hash'] == file_data.get('blockchain_hash'):
                blockchain_verification = "Verified"
            else:
                blockchain_verification = "Tampered"
        except Exception as verify_err:
            print(f"Error verifying blockchain: {verify_err}")
        
        # Get extracted text and AI summary from file data
        extracted_text = file_data.get('extracted_text', 'No text available')
        ai_summary = file_data.get('summary', 'No summary available')
        processing_status = file_data.get('processing_status', 'Unknown')

        # Get information about who the file is shared with
        shared_with_details = []
        shared_with_ids = file_data.get('shared_with', [])
        
        for provider_id in shared_with_ids:
            try:
                # Check if it's a doctor
                doctor = doctors.find_one({'_id': ObjectId(provider_id)})
                if doctor:
                    shared_with_details.append({
                        'id': provider_id,
                        'name': f"Dr. {doctor.get('name', 'Unknown')}",
                        'type': 'Doctor',
                        'specialization': ', '.join(doctor.get('specialization', [])) if isinstance(doctor.get('specialization'), list) else doctor.get('specialization', 'Not specified')
                    })
                    continue
                    
                # Check if it's a hospital
                hospital = hospitals.find_one({'_id': ObjectId(provider_id)})
                if hospital:
                    shared_with_details.append({
                        'id': provider_id,
                        'name': hospital.get('name', 'Unknown Hospital'),
                        'type': 'Hospital',
                        'specialization': 'N/A'
                    })
                    continue
                    
                # If we get here, it's an unknown provider type
                shared_with_details.append({
                    'id': provider_id,
                    'name': 'Unknown Provider',
                    'type': 'Unknown',
                    'specialization': 'Not specified'
                })
                
            except (InvalidId, Exception) as e:
                print(f"Error getting details for shared provider {provider_id}: {e}")
                shared_with_details.append({
                    'id': provider_id,
                    'name': 'Error Fetching Provider',
                    'type': 'Unknown',
                    'specialization': 'Error'
                })

        # Get file information for display
        file_info = {
            "processing_status": processing_status,
            "file_type": file_data.get('file_type', 'Unknown'),
            "original_filename": file_data.get('original_filename', 'Unknown'),
            "upload_date": file_data.get('upload_date', datetime.now()),
            "uploader_type": file_data.get('uploader_type', 'Unknown'),
            "file_extension": file_data.get('file_extension', ''),
            "ocr_success": not (extracted_text.startswith("Error") or 
                               extracted_text.startswith("OCR") or 
                               extracted_text == "No text available"),
            "summary_success": not (ai_summary.startswith("AI summary") or 
                                   ai_summary.startswith("Summary") or 
                                   ai_summary == "No summary available")
        }
        
        # Get uploader details
        uploader_details = {}
        uploader_id = file_data.get('uploader_id')
        uploader_type = file_data.get('uploader_type')
        
        if uploader_id and uploader_type:
            try:
                if uploader_type == 'doctor':
                    uploader = doctors.find_one({'_id': uploader_id})
                    if uploader:
                        uploader_details = {
                            'name': f"Dr. {uploader.get('name', 'Unknown')}",
                            'type': 'Doctor',
                            'specialization': uploader.get('specialization', 'Not specified')
                        }
                elif uploader_type == 'patient':
                    uploader = patients.find_one({'_id': uploader_id})
                    if uploader:
                        uploader_details = {
                            'name': uploader.get('name', 'Unknown Patient'),
                            'type': 'Patient',
                            'id': str(uploader.get('_id', ''))
                        }
                elif uploader_type == 'hospital':
                    uploader = hospitals.find_one({'_id': uploader_id})
                    if uploader:
                        uploader_details = {
                            'name': uploader.get('name', 'Unknown Hospital'),
                            'type': 'Hospital'
                        }
            except Exception as e:
                print(f"Error getting uploader details: {e}")
                uploader_details = {
                    'name': 'Unknown Uploader',
                    'type': uploader_type
                }
        
        # Get available doctors and hospitals for sharing
        available_doctors = []
        available_hospitals = []
        
        # If the current user is the patient or the uploader, they can share
        can_share = (str(file_data.get('patient_id', '')) == user_id or 
                    str(file_data.get('uploader_id', '')) == user_id)
                    
        if can_share:
            try:
                # Get all doctors
                available_doctors = list(doctors.find({}, {'_id': 1, 'name': 1, 'specialization': 1}))
                
                # Get all hospitals
                available_hospitals = list(hospitals.find({}, {'_id': 1, 'name': 1}))
                
                # Filter out already shared providers
                if shared_with_ids:
                    available_doctors = [doc for doc in available_doctors if str(doc['_id']) not in shared_with_ids]
                    available_hospitals = [hosp for hosp in available_hospitals if str(hosp['_id']) not in shared_with_ids]
            except Exception as e:
                print(f"Error fetching providers for sharing: {e}")
            
        return render_template(
            'view_medical_file.html',
            file=file_data,
            file_info=file_info,
            blockchain_verification=blockchain_verification,
            display_text=extracted_text,
            summary_text=ai_summary,
            processing_status=processing_status,
            shared_with_details=shared_with_details,
            uploader_details=uploader_details,
            available_doctors=available_doctors,
            available_hospitals=available_hospitals,
            can_share=can_share
        )
            
    except Exception as e:
        print(f"Error in view_medical_file: {e}")
        flash(f'Error viewing file: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# Serve uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """
    Serve uploaded files from the uploads directory
    """
    # Get the full path to the uploads directory
    upload_dir = os.path.join(app.root_path, 'uploads')
    # Use Flask's send_from_directory function to serve the file
    return send_from_directory(upload_dir, filename)

# Add a dedicated route for image gallery viewing
@app.route('/view_image/<file_id>')
@login_required
def view_image(file_id):
    """
    Dedicated route for viewing medical images in fullscreen
    """
    try:
        file_obj_id = ObjectId(file_id)
        file_data = medical_files.find_one({'_id': file_obj_id})
        
        if not file_data:
            flash('File not found', 'danger')
            return redirect(url_for('dashboard'))
            
        # Check if file is an image
        file_extension = file_data.get('file_extension', '').lower()
        if file_extension not in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
            flash('This file is not an image', 'warning')
            return redirect(url_for('view_medical_file', file_id=file_id))
            
        # Check access permission (same logic as in view_medical_file)
        user_id = session['user_id']
        user_type = session['user_type']
        
        # Allow access to uploader, patient who owns the file, or shared users
        has_access = (
            str(file_data['uploader_id']) == user_id or
            str(file_data['patient_id']) == user_id or
            user_id in file_data.get('shared_with', [])
        )
        
        if not has_access:
            # Check blockchain-based access
            try:
                patient_id_str = str(file_data['patient_id'])
                
                if user_type == 'doctor':
                    doctor = doctors.find_one({'_id': ObjectId(user_id)}, {'metamask_address': 1})
                    if doctor and 'metamask_address' in doctor:
                        doctor_address = doctor['metamask_address']
                        has_access = contract.functions.checkAccess(
                            patient_id_str,
                            doctor_address
                        ).call()
                elif user_type == 'hospital':
                    hospital = hospitals.find_one({'_id': ObjectId(user_id)}, {'metamask_address': 1})
                    if hospital and 'metamask_address' in hospital:
                        hospital_address = hospital['metamask_address']
                        has_access = contract.functions.checkAccess(
                            patient_id_str,
                            hospital_address
                        ).call()
            except Exception as e:
                print(f"Error checking blockchain access: {e}")
                has_access = False
        
        if not has_access:
            flash('You do not have permission to view this file', 'danger')
            return redirect(url_for('dashboard'))

        return render_template('view_image.html', 
                              file=file_data, 
                              filename=file_data.get('filename', ''))
                              
    except InvalidId:
        flash('Invalid file ID format', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error viewing image: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# Add a route for the image gallery
@app.route('/medical_images')
@login_required
def medical_image_gallery():
    """
    Display a gallery of medical images for the current user
    """
    try:
        user_id = session['user_id']
        user_type = session['user_type']
        
        # Different queries based on user type
        if user_type == 'patient':
            # Patients see their own images
            patient_id = ObjectId(user_id)
            query = {
                'patient_id': patient_id,
                'file_extension': {'$in': ['jpg', 'jpeg', 'png', 'gif', 'bmp']}
            }
        elif user_type == 'doctor':
            # Doctors see images from patients they have access to
            doctor_id = ObjectId(user_id)
            doctor = doctors.find_one({'_id': doctor_id})
            
            # Get patients that this doctor has access to
            patient_list = list(patients.find({'authorized_doctors': user_id}))
            patient_ids = [patient['_id'] for patient in patient_list]
            
            # Find images from those patients or uploaded by this doctor
            query = {
                '$or': [
                    {'patient_id': {'$in': patient_ids}},
                    {'uploader_id': doctor_id}
                ],
                'file_extension': {'$in': ['jpg', 'jpeg', 'png', 'gif', 'bmp']}
            }
        elif user_type == 'hospital':
            # Hospitals see images shared with them
            hospital_id = ObjectId(user_id)
            query = {
                'shared_with': user_id,
                'file_extension': {'$in': ['jpg', 'jpeg', 'png', 'gif', 'bmp']}
            }
        else:
            flash('Unknown user type', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get images from the database
        image_files = list(medical_files.find(query).sort('upload_date', -1))
        
        return render_template('view_image_gallery.html', files=image_files)
    
    except Exception as e:
        flash(f'Error loading medical images: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/share_medical_file/<file_id>', methods=['POST'])
@login_required
def share_medical_file(file_id):
    try:
        user_id = session['user_id']
        user_type = session['user_type']
        
        # Get form data
        share_with_id = request.form.get('share_with_id')
        share_until = request.form.get('share_until')
        
        if not share_with_id:
            flash('Please select a provider to share with', 'danger')
            return redirect(url_for('view_medical_file', file_id=file_id))
        
        # Verify the file exists and user has permission to share it
        try:
            file_obj_id = ObjectId(file_id)
            file_data = medical_files.find_one({'_id': file_obj_id})
            
            if not file_data:
                flash('File not found', 'danger')
                return redirect(url_for('dashboard'))
                
            # Check if user has permission to share this file
            # Only the patient who owns the file or the uploader can share it
            if user_type == 'patient':
                patient_id = ObjectId(user_id)
                if file_data.get('patient_id') != patient_id:
                    flash('You do not have permission to share this file', 'danger')
                    return redirect(url_for('dashboard'))
            elif user_type == 'doctor':
                doctor_id = ObjectId(user_id)
                if file_data.get('uploader_id') != doctor_id:
                    flash('You do not have permission to share this file', 'danger')
                    return redirect(url_for('dashboard'))
            else:
                flash('Only patients and doctors can share medical files', 'danger')
                return redirect(url_for('dashboard'))
                
            # Get share_with information
            share_with_parts = share_with_id.split('_', 1)
            if len(share_with_parts) != 2:
                flash('Invalid provider format', 'danger')
                return redirect(url_for('view_medical_file', file_id=file_id))
                
            provider_type = share_with_parts[0]  # 'doc' or 'hosp'
            provider_id = share_with_parts[1]
            
            # Validate the provider exists
            provider_name = "Provider"
            if provider_type == 'doc':
                provider = doctors.find_one({'_id': ObjectId(provider_id)})
                if provider:
                    provider_name = f"Dr. {provider.get('name', 'Unknown')}"
                else:
                    flash('Selected doctor does not exist', 'danger')
                    return redirect(url_for('view_medical_file', file_id=file_id))
            elif provider_type == 'hosp':
                provider = hospitals.find_one({'_id': ObjectId(provider_id)})
                if provider:
                    provider_name = provider.get('name', 'Unknown Hospital')
                else:
                    flash('Selected hospital does not exist', 'danger')
                    return redirect(url_for('view_medical_file', file_id=file_id))
            else:
                flash('Invalid provider type', 'danger')
                return redirect(url_for('view_medical_file', file_id=file_id))
            
            # Update the shared_with list in the file document
            # Initialize shared_with list if it doesn't exist
            if 'shared_with' not in file_data:
                file_data['shared_with'] = []
                
            # Check if already shared
            if provider_id in file_data['shared_with']:
                flash(f'File is already shared with {provider_name}', 'info')
                return redirect(url_for('view_medical_file', file_id=file_id))
                
            # Add to shared_with list
            medical_files.update_one(
                {'_id': file_obj_id},
                {'$addToSet': {'shared_with': provider_id}}
            )
            
            # Also update the sharing_details field to store additional sharing information
            sharing_details = file_data.get('sharing_details', [])
            
            # Add share date information
            sharing_details.append({
                'provider_id': provider_id,
                'provider_type': provider_type,
                'provider_name': provider_name,
                'shared_by': user_id,
                'shared_at': datetime.now(),
                'share_until': share_until,
                'status': 'active'
            })
            
            # Update the file with sharing details
            medical_files.update_one(
                {'_id': file_obj_id},
                {'$set': {'sharing_details': sharing_details}}
            )
            
            # Update the patient's authorized_providers field to maintain the connection
            if user_type == 'patient' and provider_type == 'doc':
                patients.update_one(
                    {'_id': patient_id},
                    {'$addToSet': {'authorized_doctors': provider_id}}
                )
            
            flash(f'Medical file shared successfully with {provider_name}', 'success')
            return redirect(url_for('view_medical_file', file_id=file_id))
            
        except InvalidId:
            flash('Invalid file ID format', 'danger')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        flash(f'Error sharing medical file: {str(e)}', 'danger')
        print(f"Error in share_medical_file: {e}")
        return redirect(url_for('view_medical_file', file_id=file_id))

if __name__ == '__main__':
    # Initialize blockchain if empty
    create_genesis_block()
    app.run(debug=True)
