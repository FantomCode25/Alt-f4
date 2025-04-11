// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Healthcare {
    address public owner;
    
    struct Hospital {
        string name;
        address walletAddress;
        bool isRegistered;
    }
    
    struct Doctor {
        string name;
        string specialization;
        address walletAddress;
        bool isRegistered;
    }
    
    struct Patient {
        string name;
        string patientId;
        string bloodGroup;
        address walletAddress;
        string publicKey; // Patient's public key for encryption
        bool isActive;
    }
    
    struct MedicalRecord {
        string patientId;
        string recordId;  // MongoDB ID reference
        string condition;
        string date;
        address[] authorizedAccess;  // List of addresses with access
    }
    
    struct Examination {
        string patientId;
        string examinationId;  // MongoDB ID reference
        string diagnosis;
        string date;
        address[] authorizedAccess;  // List of addresses with access
    }
    
    struct AccessControl {
        address grantedBy;
        address grantedTo;
        uint256 expiryTime;
        string[] allowedFields; // Specific fields that can be accessed
        bool isRevoked;
    }
    
    struct ResearchAgreement {
        address researcher;
        string purpose;
        uint256 compensation;
        uint256 expiryTime;
        bool isActive;
        string[] allowedFields;
    }
    
    mapping(address => Hospital) public hospitals;
    mapping(address => Doctor) public doctors;
    mapping(string => Patient) public patients;
    mapping(string => MedicalRecord[]) public medicalRecords;
    mapping(string => Examination[]) public examinations;
    mapping(string => mapping(address => bool)) public patientAccess;  // Patient ID => Address => Has Access
    mapping(string => mapping(address => AccessControl)) public accessControls;
    mapping(string => ResearchAgreement[]) public researchAgreements;
    mapping(string => string) public encryptedRecords;
    
    event HospitalRegistered(string name, address walletAddress);
    event DoctorRegistered(string name, string specialization, address walletAddress);
    event PatientRegistered(string patientId, address walletAddress);
    event MedicalRecordAdded(string patientId, string recordId, string condition, string date);
    event ExaminationAdded(string patientId, string examinationId, string diagnosis, string date);
    event AccessGranted(string patientId, address grantedTo, uint256 expiryTime);
    event AccessRevoked(string patientId, address revokedFrom);
    event ResearchAgreementCreated(string patientId, address researcher, uint256 compensation);
    event RecordEncrypted(string patientId, string encryptedData);
    event ZeroKnowledgeProofVerified(string patientId, address verifier);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier onlyPatient(string memory _patientId) {
        require(patients[_patientId].walletAddress == msg.sender, "Only patient can call this function");
        _;
    }
    
    modifier hasAccess(string memory _patientId) {
        require(
            patients[_patientId].walletAddress == msg.sender || 
            patientAccess[_patientId][msg.sender],
            "No access to this patient's data"
        );
        _;
    }
    
    modifier hasValidAccess(string memory patientId) {
        require(
            patients[patientId].walletAddress == msg.sender ||
            (accessControls[patientId][msg.sender].expiryTime > block.timestamp && 
             !accessControls[patientId][msg.sender].isRevoked),
            "No valid access"
        );
        _;
    }
    
    function registerHospital(string memory _name, address _walletAddress) public {
        hospitals[_walletAddress] = Hospital(_name, _walletAddress, true);
        emit HospitalRegistered(_name, _walletAddress);
    }
    
    function registerDoctor(string memory _name, string memory _specialization, address _walletAddress) public {
        doctors[_walletAddress] = Doctor(_name, _specialization, _walletAddress, true);
        emit DoctorRegistered(_name, _specialization, _walletAddress);
    }
    
    function registerPatient(
        string memory name,
        string memory patientId,
        string memory bloodGroup,
        string memory publicKey
    ) public {
        require(patients[patientId].walletAddress == address(0), "Patient already registered");
        
        patients[patientId] = Patient({
            name: name,
            patientId: patientId,
            bloodGroup: bloodGroup,
            walletAddress: msg.sender,
            publicKey: publicKey,
            isActive: true
        });

        emit PatientRegistered(patientId, msg.sender);
    }
    
    function addMedicalRecord(string memory _patientId, string memory _recordId, string memory _condition, string memory _date) public hasAccess(_patientId) {
        require(patients[_patientId].isActive, "Patient must be active");
        
        MedicalRecord memory newRecord = MedicalRecord(_patientId, _recordId, _condition, _date, new address[](0));
        newRecord.authorizedAccess.push(msg.sender);  // Grant access to the creator
        medicalRecords[_patientId].push(newRecord);
        
        emit MedicalRecordAdded(_patientId, _recordId, _condition, _date);
    }
    
    function addExamination(string memory _patientId, string memory _examinationId, string memory _diagnosis, string memory _date) public hasAccess(_patientId) {
        require(patients[_patientId].isActive, "Patient must be active");
        
        Examination memory newExamination = Examination(_patientId, _examinationId, _diagnosis, _date, new address[](0));
        newExamination.authorizedAccess.push(msg.sender);  // Grant access to the creator
        examinations[_patientId].push(newExamination);
        
        emit ExaminationAdded(_patientId, _examinationId, _diagnosis, _date);
    }
    
    function grantAccess(
        string memory patientId,
        address grantedTo,
        uint256 duration,
        string[] memory allowedFields
    ) public onlyPatient(patientId) {
        require(grantedTo != address(0), "Invalid address");
        
        accessControls[patientId][grantedTo] = AccessControl({
            grantedBy: msg.sender,
            grantedTo: grantedTo,
            expiryTime: block.timestamp + duration,
            allowedFields: allowedFields,
            isRevoked: false
        });

        emit AccessGranted(patientId, grantedTo, block.timestamp + duration);
    }
    
    function revokeAccess(string memory patientId, address grantedTo) public onlyPatient(patientId) {
        require(accessControls[patientId][grantedTo].grantedTo != address(0), "No access granted");
        accessControls[patientId][grantedTo].isRevoked = true;
        emit AccessRevoked(patientId, grantedTo);
    }
    
    function getPatientDetails(string memory _patientId) public view hasAccess(_patientId) returns (string memory, string memory, string memory) {
        require(patients[_patientId].isActive, "Patient not active");
        Patient memory patient = patients[_patientId];
        return (patient.name, patient.patientId, patient.bloodGroup);
    }
    
    function getMedicalRecordsCount(string memory _patientId) public view hasAccess(_patientId) returns (uint256) {
        return medicalRecords[_patientId].length;
    }
    
    function getExaminationsCount(string memory _patientId) public view hasAccess(_patientId) returns (uint256) {
        return examinations[_patientId].length;
    }
    
    function checkAccess(string memory _patientId, address _address) public view returns (bool) {
        return patientAccess[_patientId][_address] || patients[_patientId].walletAddress == _address;
    }
    
    function storeEncryptedRecord(
        string memory patientId,
        string memory encryptedData
    ) public hasValidAccess(patientId) {
        encryptedRecords[patientId] = encryptedData;
        emit RecordEncrypted(patientId, encryptedData);
    }
    
    function createResearchAgreement(
        string memory patientId,
        address researcher,
        string memory purpose,
        uint256 compensation,
        uint256 duration,
        string[] memory allowedFields
    ) public onlyPatient(patientId) {
        researchAgreements[patientId].push(ResearchAgreement({
            researcher: researcher,
            purpose: purpose,
            compensation: compensation,
            expiryTime: block.timestamp + duration,
            isActive: true,
            allowedFields: allowedFields
        }));

        emit ResearchAgreementCreated(patientId, researcher, compensation);
    }
    
    function verifyZeroKnowledgeProof(
        string memory patientId,
        bytes memory proof
    ) public returns (bool) {
        // This is a placeholder for actual ZKP verification
        // In a real implementation, this would verify the proof using a ZKP library
        emit ZeroKnowledgeProofVerified(patientId, msg.sender);
        return true;
    }
    
    function getPatientPublicKey(string memory patientId) public view returns (string memory) {
        return patients[patientId].publicKey;
    }
    
    function hasAccessToFields(
        string memory patientId,
        address user,
        string[] memory fields
    ) public view returns (bool) {
        if (patients[patientId].walletAddress == user) return true;
        
        AccessControl storage access = accessControls[patientId][user];
        if (access.expiryTime <= block.timestamp || access.isRevoked) return false;

        for (uint i = 0; i < fields.length; i++) {
            bool fieldAllowed = false;
            for (uint j = 0; j < access.allowedFields.length; j++) {
                if (keccak256(bytes(fields[i])) == keccak256(bytes(access.allowedFields[j]))) {
                    fieldAllowed = true;
                    break;
                }
            }
            if (!fieldAllowed) return false;
        }
        return true;
    }
}