/**
 * MetaMask Integration Utilities
 * 
 * This file contains utilities for integrating MetaMask with the Healthcare Blockchain application.
 * It provides functions for connecting to MetaMask, signing transactions, and interacting with
 * the Healthcare smart contract.
 */

// Store the current web3 instance
let web3;
let healthcareContract;
let currentAccount;
let contractAddress = '0x5B38Da6a701c568545dCfcB03FcB875f56beddC4'; // Update with actual contract address

/**
 * Initialize the connection to MetaMask and set up the contract
 */
async function initializeWeb3() {
    // Check if MetaMask is installed
    if (typeof window.ethereum !== 'undefined') {
        try {
            // Request account access
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            currentAccount = accounts[0];
            
            // Create Web3 instance
            web3 = new Web3(window.ethereum);
            
            // Get the contract ABI
            const response = await fetch('/static/contract_abi.json');
            const contractABI = await response.json();
            
            // Create contract instance
            healthcareContract = new web3.eth.Contract(
                contractABI,
                contractAddress
            );
            
            // Update UI to show connected status
            updateConnectionStatus(true, currentAccount);
            
            // Set up event listener for account changes
            window.ethereum.on('accountsChanged', handleAccountsChanged);
            
            return true;
        } catch (error) {
            console.error("Error initializing Web3:", error);
            updateConnectionStatus(false);
            return false;
        }
    } else {
        console.log("MetaMask is not installed");
        updateConnectionStatus(false);
        
        // Display MetaMask installation instructions
        const metamaskMsg = document.getElementById('metamask-message');
        if (metamaskMsg) {
            metamaskMsg.innerHTML = 'Please install <a href="https://metamask.io/" target="_blank">MetaMask</a> to use blockchain features.';
            metamaskMsg.style.display = 'block';
        }
        return false;
    }
}

/**
 * Handle account changes in MetaMask
 */
function handleAccountsChanged(accounts) {
    if (accounts.length === 0) {
        // MetaMask is locked or the user has not connected any accounts
        console.log('Please connect to MetaMask.');
        updateConnectionStatus(false);
    } else if (accounts[0] !== currentAccount) {
        currentAccount = accounts[0];
        updateConnectionStatus(true, currentAccount);
        console.log('Active account changed to:', currentAccount);
    }
}

/**
 * Update the UI to show connection status
 */
function updateConnectionStatus(connected, account = null) {
    const statusElement = document.getElementById('metamask-status');
    if (!statusElement) return;
    
    if (connected) {
        statusElement.innerHTML = `Connected: ${account.substring(0, 6)}...${account.substring(account.length - 4)}`;
        statusElement.className = 'connected';
        
        // Enable blockchain action buttons
        document.querySelectorAll('.requires-metamask').forEach(el => {
            el.removeAttribute('disabled');
        });
    } else {
        statusElement.innerHTML = 'Not Connected';
        statusElement.className = 'disconnected';
        
        // Disable blockchain action buttons
        document.querySelectorAll('.requires-metamask').forEach(el => {
            el.setAttribute('disabled', 'disabled');
        });
    }
}

/**
 * Grant access to a doctor or hospital from patient's wallet
 */
async function grantAccessFromWallet(patientId, providerAddress, durationSeconds, allowedFields) {
    if (!web3 || !healthcareContract || !currentAccount) {
        console.error("Web3 or contract not initialized");
        return {success: false, error: "Wallet not connected"};
    }
    
    try {
        // Create transaction
        const transaction = healthcareContract.methods.grantAccess(
            patientId,
            providerAddress,
            durationSeconds,
            allowedFields
        );
        
        // Estimate gas
        const gas = await transaction.estimateGas({from: currentAccount});
        
        // Send transaction
        const receipt = await transaction.send({
            from: currentAccount,
            gas: Math.floor(gas * 1.2) // Add 20% buffer
        });
        
        return {
            success: true, 
            transactionHash: receipt.transactionHash,
            blockNumber: receipt.blockNumber
        };
    } catch (error) {
        console.error("Error granting access:", error);
        return {success: false, error: error.message};
    }
}

/**
 * Register patient from patient's wallet
 */
async function registerPatientFromWallet(name, patientId, bloodGroup, publicKey) {
    if (!web3 || !healthcareContract || !currentAccount) {
        console.error("Web3 or contract not initialized");
        return {success: false, error: "Wallet not connected"};
    }
    
    try {
        // Create transaction
        const transaction = healthcareContract.methods.registerPatient(
            name,
            patientId,
            bloodGroup,
            publicKey
        );
        
        // Estimate gas
        const gas = await transaction.estimateGas({from: currentAccount});
        
        // Send transaction
        const receipt = await transaction.send({
            from: currentAccount,
            gas: Math.floor(gas * 1.2) // Add 20% buffer
        });
        
        return {
            success: true, 
            transactionHash: receipt.transactionHash,
            blockNumber: receipt.blockNumber
        };
    } catch (error) {
        console.error("Error registering patient:", error);
        return {success: false, error: error.message};
    }
}

/**
 * Connect button handler
 */
async function connectWallet() {
    const success = await initializeWeb3();
    if (success) {
        // You might want to refresh certain UI elements here
        console.log("Successfully connected to MetaMask");
    } else {
        console.log("Failed to connect to MetaMask");
    }
} 