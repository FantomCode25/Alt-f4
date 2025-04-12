// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Healthcare {
    // Structs
    struct Patient {
        string name;
        string publicKey;
        bool exists;
        mapping(address => bool) authorizedUsers;
        mapping(address => uint256) accessExpiry;
        mapping(address => string[]) allowedFields;
        mapping(address => bool) isDoctor;
        mapping(address => bool) isHospital;
    }

    struct Hospital {
        string name;
        string location;
        bool exists;
    }

    struct Doctor {
        string name;
        string specialization;
        address hospitalAddress;
        bool exists;
    }

    struct MedicalRecord {
        string ipfsHash;
        string encryptedData;
        string abstract;
        address uploadedBy;
        uint256 timestamp;
        bool exists;
    }

    // Events
    event PatientRegistered(address indexed patientAddress, string name);
    event HospitalRegistered(address indexed hospitalAddress, string name);
    event DoctorRegistered(address indexed doctorAddress, string name);
    event AccessGranted(address indexed patientAddress, address indexed grantedTo, uint256 expiry);
    event AccessRevoked(address indexed patientAddress, address indexed revokedFrom);
    event MedicalRecordAdded(address indexed patientAddress, string ipfsHash);
    event EmergencyAccessGranted(address indexed patientAddress, address indexed grantedTo);

    // Mappings
    mapping(address => Patient) public patients;
    mapping(address => Hospital) public hospitals;
    mapping(address => Doctor) public doctors;
    mapping(address => mapping(uint256 => MedicalRecord)) public medicalRecords;
    mapping(address => uint256) public patientRecordCount;

    // Emergency access
    mapping(address => mapping(address => bool)) public emergencyAccess;
    mapping(address => string) public emergencyPins;

    // Modifiers
    modifier onlyPatient(address _patientAddress) {
        require(msg.sender == _patientAddress, "Only patient can perform this action");
        _;
    }

    modifier onlyHospital() {
        require(hospitals[msg.sender].exists, "Only hospitals can perform this action");
        _;
    }

    modifier onlyDoctor() {
        require(doctors[msg.sender].exists, "Only doctors can perform this action");
        _;
    }

    // Patient Registration
    function registerPatient(string memory _name, string memory _publicKey) public {
        require(!patients[msg.sender].exists, "Patient already registered");
        
        Patient storage newPatient = patients[msg.sender];
        newPatient.name = _name;
        newPatient.publicKey = _publicKey;
        newPatient.exists = true;
        
        emit PatientRegistered(msg.sender, _name);
    }

    // Hospital Registration
    function registerHospital(string memory _name, string memory _location) public {
        require(!hospitals[msg.sender].exists, "Hospital already registered");
        
        hospitals[msg.sender] = Hospital({
            name: _name,
            location: _location,
            exists: true
        });
        
        emit HospitalRegistered(msg.sender, _name);
    }

    // Doctor Registration
    function registerDoctor(string memory _name, string memory _specialization) public onlyHospital {
        require(!doctors[msg.sender].exists, "Doctor already registered");
        
        doctors[msg.sender] = Doctor({
            name: _name,
            specialization: _specialization,
            hospitalAddress: msg.sender,
            exists: true
        });
        
        emit DoctorRegistered(msg.sender, _name);
    }

    // Access Control
    function grantAccess(
        address _userAddress,
        uint256 _duration,
        string[] memory _allowedFields,
        bool _isDoctor,
        bool _isHospital
    ) public onlyPatient(msg.sender) {
        require(_userAddress != msg.sender, "Cannot grant access to self");
        
        Patient storage patient = patients[msg.sender];
        patient.authorizedUsers[_userAddress] = true;
        patient.accessExpiry[_userAddress] = block.timestamp + _duration;
        patient.allowedFields[_userAddress] = _allowedFields;
        patient.isDoctor[_userAddress] = _isDoctor;
        patient.isHospital[_userAddress] = _isHospital;
        
        emit AccessGranted(msg.sender, _userAddress, block.timestamp + _duration);
    }

    function revokeAccess(address _userAddress) public onlyPatient(msg.sender) {
        Patient storage patient = patients[msg.sender];
        patient.authorizedUsers[_userAddress] = false;
        patient.accessExpiry[_userAddress] = 0;
        patient.isDoctor[_userAddress] = false;
        patient.isHospital[_userAddress] = false;
        
        emit AccessRevoked(msg.sender, _userAddress);
    }

    // Medical Records
    function addMedicalRecord(
        address _patientAddress,
        string memory _ipfsHash,
        string memory _encryptedData,
        string memory _abstract
    ) public {
        require(patients[_patientAddress].exists, "Patient not registered");
        require(
            msg.sender == _patientAddress || 
            patients[_patientAddress].authorizedUsers[msg.sender],
            "Not authorized"
        );
        require(
            patients[_patientAddress].accessExpiry[msg.sender] > block.timestamp,
            "Access expired"
        );
        
        uint256 recordId = patientRecordCount[_patientAddress]++;
        medicalRecords[_patientAddress][recordId] = MedicalRecord({
            ipfsHash: _ipfsHash,
            encryptedData: _encryptedData,
            abstract: _abstract,
            uploadedBy: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });
        
        emit MedicalRecordAdded(_patientAddress, _ipfsHash);
    }

    // Emergency Access
    function setEmergencyPin(string memory _pin) public onlyPatient(msg.sender) {
        emergencyPins[msg.sender] = _pin;
    }

    function grantEmergencyAccess(address _patientAddress, string memory _pin) public {
        require(keccak256(bytes(emergencyPins[_patientAddress])) == keccak256(bytes(_pin)), "Invalid PIN");
        emergencyAccess[_patientAddress][msg.sender] = true;
        
        emit EmergencyAccessGranted(_patientAddress, msg.sender);
    }

    // Getters
    function getPatientInfo(address _patientAddress) public view returns (
        string memory name,
        string memory publicKey,
        bool exists
    ) {
        Patient storage patient = patients[_patientAddress];
        return (patient.name, patient.publicKey, patient.exists);
    }

    function getMedicalRecord(address _patientAddress, uint256 _recordId) public view returns (
        string memory ipfsHash,
        string memory encryptedData,
        string memory abstract,
        address uploadedBy,
        uint256 timestamp
    ) {
        require(medicalRecords[_patientAddress][_recordId].exists, "Record not found");
        require(
            msg.sender == _patientAddress || 
            patients[_patientAddress].authorizedUsers[msg.sender] || 
            emergencyAccess[_patientAddress][msg.sender],
            "Not authorized"
        );
        
        MedicalRecord storage record = medicalRecords[_patientAddress][_recordId];
        return (
            record.ipfsHash,
            record.encryptedData,
            record.abstract,
            record.uploadedBy,
            record.timestamp
        );
    }

    function checkAccess(address _patientAddress, address _requester) public view returns (bool) {
        return patients[_patientAddress].authorizedUsers[_requester] && 
               patients[_patientAddress].accessExpiry[_requester] > block.timestamp;
    }

    function getUserType(address _patientAddress, address _userAddress) public view returns (
        bool isDoctor,
        bool isHospital
    ) {
        Patient storage patient = patients[_patientAddress];
        return (
            patient.isDoctor[_userAddress],
            patient.isHospital[_userAddress]
        );
    }
} 