# 🏥 HealthChain - Secure Medical Records on Blockchain

Team Name: Altf4  
Hackathon: Fantomcode 25  
Date: 12/04/2025

## 📖 Table of Contents
- [Introduction](#introduction)
- [Problem Statement](#problem-statement)
- [Solution Overview](#solution-overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Installation & Usage](#installation--usage)
- [Team Members](#team-members)

## 🧠 Introduction
HealthChain is a decentralized medical records management system that leverages blockchain technology to ensure the security, integrity, and controlled sharing of sensitive patient data. The platform enables patients to own their medical data while selectively granting access to healthcare providers, enhancing privacy and data accessibility in the healthcare ecosystem.

## ❗ Problem Statement
The healthcare industry faces significant challenges with medical record management:
- Patient data is fragmented across different healthcare providers
- Patients lack control over who can access their medical records
- Data breaches regularly expose sensitive medical information
- Lack of interoperability between different healthcare systems
- Difficulty in verifying the authenticity and integrity of medical records

## ✅ Solution Overview
HealthChain addresses these challenges by creating a blockchain-based medical records platform with the following capabilities:

- **Patient-Controlled Access**: Patients maintain full ownership of their medical data, deciding who can view or modify their records.
- **Secure Data Storage**: Medical records are encrypted and stored with blockchain verification.
- **OCR & AI Processing**: Automatic extraction of data from medical documents and AI-generated summaries.
- **Selective Sharing**: Granular control over data sharing with doctors and healthcare institutions.
- **Blockchain Verification**: All medical records are verified on a blockchain network, ensuring data integrity.
- **Emergency Access**: Special emergency access mechanisms for critical situations.

## 🛠️ Tech Stack
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Backend**: Python, Flask
- **Database**: MongoDB
- **Blockchain**: Ethereum/Ganache (Web3.py)
- **AI & Processing**:
  - Google Generative AI for summaries
  - OCR for document text extraction
  - PyTesseract for fallback text extraction
- **Security**: RSA encryption, blockchain integrity verification
- **Tools**: Git, Docker

## 🧩 Architecture
The system is built on a three-tier architecture:

1. **Web Interface Layer**: Patient, doctor, and hospital dashboards
2. **Application Layer**: Flask server handling authentication, file processing, and data management
3. **Storage & Blockchain Layer**: MongoDB for data storage, Ethereum blockchain for verification

The platform uses a hybrid storage approach where:
- Document metadata and access controls are stored on the blockchain
- Actual medical files and extracted text are stored in MongoDB
- File paths are stored in the database with the actual files on secure storage

## 🌟 Key Features

### For Patients
- Upload and manage medical records
- Control access to medical data
- View a timeline of medical history
- Set up emergency access for critical situations
- Image gallery for medical images

### For Doctors
- Access authorized patient records
- Upload medical files for patients
- View shared medical images
- Receive secure access to patient data

### For Hospitals
- Manage affiliated doctors
- Access authorized patient information
- Secure data sharing with other providers

### Technical Features
- Automatic OCR processing of uploaded documents
- AI-generated summaries of medical documents
- Blockchain verification of document integrity
- Secure encryption of sensitive patient data
- Real-time access control management

## 🧪 Installation & Usage

### Prerequisites
- Python 3.8+
- MongoDB
- Ganache (local blockchain)
- Tesseract OCR (optional, for fallback text extraction)

### Steps

```bash
# Clone the repository
git clone https://github.com/altf4-team.git

# Navigate into the project directory
cd healthchain

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start MongoDB
mongod --dbpath /path/to/db

# Start Ganache (local blockchain)
ganache-cli

# Set up environment variables
# Create a .env file with necessary API keys and configuration

# Initialize the application
python app.py
```

### Environment Setup

Create a `.env` file with the following variables:
```
GOOGLE_API_KEY=your_google_api_key
OCR_API_KEY=your_ocr_api_key
SECRET_KEY=your_flask_secret_key
```

## 👥 Team Members
- [Praveen Ketannavar] 
- [Priya Patil] 
- [Nidhi H] 
- [Priyanka K] 
