// public/app.js

// Constants for IndexedDB
const DB_NAME = 'SecureVaultDB';
const DB_VERSION = 1;
const STORE_NAME = 'vaultStore';
const MASTER_KEY_ITERATIONS = 100000; // PBKDF2 iterations for master password key derivation
const AUTOLOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds

// DOM Elements
const appContainer = document.getElementById('app-container');
const messageBox = document.getElementById('message-box');
const globalErrorMessage = document.getElementById('global-error-message'); // New global error element
const globalErrorText = document.getElementById('global-error-text'); // New element for error text
const loadingMessage = document.getElementById('loading-message'); // New loading message element

// Auth Screen Elements
const authScreen = document.getElementById('auth-screen');
const authTitle = document.getElementById('auth-title');
const authDescription = document.getElementById('auth-description');
const masterPasswordInput = document.getElementById('master-password');
const confirmPasswordGroup = document.getElementById('confirm-password-group');
const confirmMasterPasswordInput = document.getElementById('confirm-master-password');
const authButton = document.getElementById('auth-button');
const importExistingVaultButton = document.getElementById('import-existing-vault-button');

// Vault View Elements
const vaultView = document.getElementById('vault-view');
const searchVaultInput = document.getElementById('search-vault');
const addEntryButton = document.getElementById('add-entry-button');
const generatePasswordButton = document.getElementById('generate-password-button');
const vaultList = document.getElementById('vault-list');
const noEntriesMessage = document.getElementById('no-entries-message');
const exportVaultButton = document.getElementById('export-vault-button');
const importVaultFileInput = document.getElementById('import-vault-file-input');
const triggerImportVaultButton = document.getElementById('trigger-import-vault-button');
// New element for changing master password
const changeMasterPasswordButton = document.getElementById('change-master-password-button');


// Header Elements
const statusIcon = document.getElementById('status-icon');
const statusText = document.getElementById('status-text');
const lockButton = document.getElementById('lock-button');

// Entry Modal Elements
const entryModal = document.getElementById('entry-modal');
const entryModalTitle = document.getElementById('entry-modal-title');
const entryForm = document.getElementById('entry-form');
const entryUrlInput = document.getElementById('entry-url');
const entryUsernameInput = document.getElementById('entry-username');
const entryPasswordInput = document.getElementById('entry-password');
const toggleEntryPasswordVisibility = document.getElementById('toggle-entry-password-visibility');
const entryNotesInput = document.getElementById('entry-notes');
const cancelEntryButton = document.getElementById('cancel-entry-button');
const saveEntryButton = document.getElementById('save-entry-button');

// Password Generator Modal Elements
const generatorModal = document.getElementById('generator-modal');
const generatedPasswordDisplay = document.getElementById('generated-password-display');
const copyGeneratedPasswordButton = document.getElementById('copy-generated-password');
const generatedPasswordStrength = document.getElementById('generated-password-strength');
const passwordLengthInput = document.getElementById('password-length');
const lengthValueSpan = document.getElementById('length-value');
const includeUppercaseCheckbox = document.getElementById('include-uppercase');
const includeLowercaseCheckbox = document.getElementById('include-lowercase');
const includeNumbersCheckbox = document.getElementById('include-numbers');
const includeSymbolsCheckbox = document.getElementById('include-symbols');
const cancelGeneratorButton = document.getElementById('cancel-generator-button');
const generateNewPasswordButton = document.getElementById('generate-new-password-button');
const useGeneratedPasswordButton = document.getElementById('use-generated-password-button');

// Confirm Delete Modal Elements
const confirmDeleteModal = document.getElementById('confirm-delete-modal');
const cancelDeleteButton = document.getElementById('cancel-delete-button');
const confirmDeleteButton = document.getElementById('confirm-delete-button');

// Change Master Password Modal Elements (new)
const changeMasterPasswordModal = document.getElementById('change-master-password-modal');
const currentMasterPasswordInput = document.getElementById('current-master-password');
const newMasterPasswordInput = document.getElementById('new-master-password');
const confirmNewMasterPasswordInput = document.getElementById('confirm-new-master-password');
const cancelChangePasswordButton = document.getElementById('cancel-change-password-button');
const saveNewMasterPasswordButton = document.getElementById('save-new-master-password-button');


// Global State Variables
let db; // IndexedDB database instance
let isAuthenticated = false;
let vaultEncryptionKey = null; // AES-256-GCM key derived from master password
let vaultData = []; // Decrypted array of vault entries
let currentEditEntryId = null; // To track which entry is being edited
let autolockTimer;
let passwordToUseInEntryModal = ''; // To pass generated password to entry modal


// --- Utility Functions ---

/**
 * Displays a message to the user.
 * @param {string} message The message to display.
 * @param {'success'|'error'|'info'} type The type of message (influences styling).
 */
function showMessage(message, type) {
    messageBox.textContent = message;
    messageBox.className = `mb-4 p-3 rounded-lg text-sm text-center ${type === 'success' ? 'message-success' : type === 'error' ? 'message-error' : 'message-info'} block`;
    messageBox.classList.remove('hidden');
    // Hide message after 5 seconds
    setTimeout(() => {
        messageBox.classList.add('hidden');
    }, 5000);
}

/**
 * Displays a critical, non-dismissible error message and hides the main app.
 * @param {string} message The error message to display.
 */
function showGlobalError(message) {
    if (loadingMessage) {
        loadingMessage.classList.add('hidden'); // Hide loading message
    }
    if (globalErrorMessage && globalErrorText && appContainer) {
        globalErrorText.textContent = message;
        globalErrorMessage.classList.remove('hidden'); // Show global error
        appContainer.classList.add('hidden'); // Hide main app if critical error
    } else {
        // Fallback if elements aren't found (e.g., HTML not fully loaded)
        console.error('Critical Error: ' + message);
        document.body.innerHTML = `<div style="padding: 20px; color: red; text-align: center; font-family: sans-serif;">
                                    <h1>Fatal Error</h1>
                                    <p>${message}</p>
                                    <p>Please check your browser console (F12) for more details.</p>
                                   </div>`;
    }
}

/**
 * Converts a string to an ArrayBuffer.
 * @param {string} str The string to convert.
 * @returns {ArrayBuffer} The ArrayBuffer representation of the string.
 */
function strToArrayBuffer(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

/**
 * Converts an ArrayBuffer to a string.
 * @param {ArrayBuffer} buffer The ArrayBuffer to convert.
 * @returns {string} The string representation of the ArrayBuffer.
 */
function arrayBufferToStr(buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

/**
 * Converts an ArrayBuffer to a Base64 string.
 * @param {ArrayBuffer} buffer The ArrayBuffer to convert.
 * @returns {string} The Base64 encoded string.
 */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

/**
 * Converts a Base64 string to an ArrayBuffer.
 * @param {string} base64 The Base64 string to convert.
 * @returns {ArrayBuffer} The ArrayBuffer representation.
 */
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Generates a random Initialization Vector (IV) for AES-GCM.
 * @returns {Uint8Array} A 12-byte (96-bit) IV.
 */
function generateIv() {
    return window.crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Derives a cryptographic key from a password using PBKDF2.
 * @param {string} password The user's master password.
 * @param {Uint8Array} salt A unique salt for key derivation.
 * @returns {Promise<CryptoKey>} The derived CryptoKey.
 */
async function deriveKeyFromPassword(password, salt) {
    const pwBuffer = strToArrayBuffer(password);
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        pwBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: MASTER_KEY_ITERATIONS,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Generates a new AES-256-GCM key.
 * @returns {Promise<CryptoKey>} A new AES-256-GCM key.
 */
async function generateAESKey() {
    return window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypts data using AES-256-GCM.
 * @param {string} data The data to encrypt.
 * @param {CryptoKey} key The encryption key.
 * @param {Uint8Array} iv The Initialization Vector.
 * @returns {Promise<string>} Base64 encoded ciphertext.
 */
async function encryptData(data, key, iv) {
    const dataBuffer = strToArrayBuffer(data);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
        },
        key,
        dataBuffer
    );
    return arrayBufferToBase64(encryptedBuffer);
}

/**
 * Decrypts data using AES-256-GCM.
 * @param {string} encryptedData Base64 encoded ciphertext.
 * @param {CryptoKey} key The decryption key.
 * @param {Uint8Array} iv The Initialization Vector.
 * @returns {Promise<string>} The decrypted plaintext data.
 */
async function decryptData(encryptedData, key, iv) {
    try {
        const encryptedBuffer = base64ToArrayBuffer(encryptedData);
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            key,
            encryptedBuffer
        );
        return arrayBufferToStr(decryptedBuffer);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Decryption failed. Incorrect password or corrupted data.');
    }
}

/**
 * Exports a CryptoKey to a Base64 string.
 * @param {CryptoKey} key The CryptoKey to export.
 * @returns {Promise<string>} Base64 encoded key.
 */
async function exportKey(key) {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    return arrayBufferToBase64(exported);
}

/**
 * Imports a CryptoKey from a Base64 string.
 * @param {string} base64Key Base64 encoded key.
 * @returns {Promise<CryptoKey>} The imported CryptoKey.
 */
async function importKey(base64Key) {
    const buffer = base64ToArrayBuffer(base64Key);
    return window.crypto.subtle.importKey(
        'raw',
        buffer,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Copy text to clipboard and then clear it with a placeholder after a delay.
 * @param {string} text The text to copy.
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showMessage('Copied to clipboard! Clearing in 10 seconds...', 'success');
        setTimeout(async () => {
            // Attempt to write a blank string or a placeholder to "clear" it
            // Note: True clipboard clearing is not possible for security reasons.
            // This just overwrites it with something innocuous.
            await navigator.clipboard.writeText('');
            showMessage('Clipboard cleared (overwritten with empty string).', 'info');
        }, 10000); // Clear after 10 seconds
    } catch (err) {
        console.error('Failed to copy text: ', err);
        showMessage('Failed to copy to clipboard. Ensure site has permission.', 'error');
    }
}

// --- IndexedDB Functions ---

/**
 * Initializes the IndexedDB database.
 * @returns {Promise<IDBDatabase>} A promise that resolves with the database instance.
 */
function initDb() {
    return new Promise((resolve, reject) => {
        // Check for IndexedDB support
        if (!window.indexedDB) {
            reject(new Error("IndexedDB is not supported by your browser. This application cannot run."));
            return;
        }

        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            // Create an object store to hold our vault data
            // We'll only have one record in this store (the entire encrypted vault)
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
        };

        request.onsuccess = (event) => {
            db = event.target.result;
            resolve(db);
        };

        request.onerror = (event) => {
            console.error('IndexedDB error:', event.target.error);
            reject(new Error(`IndexedDB initialization failed: ${event.target.error.message}`));
        };
    });
}

/**
 * Stores encrypted vault data in IndexedDB.
 * @param {object} encryptedData The encrypted vault data object to store.
 * @returns {Promise<void>}
 */
async function storeEncryptedVault(encryptedData) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('IndexedDB not initialized. Cannot store data.'));
            return;
        }
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        // We'll use a fixed ID since there's only one vault per user
        const request = store.put({ id: 'vaultData', ...encryptedData });

        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
    });
}

/**
 * Retrieves encrypted vault data from IndexedDB.
 * @returns {Promise<object|undefined>} The encrypted vault data, or undefined if not found.
 */
async function getEncryptedVault() {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('IndexedDB not initialized. Cannot retrieve data.'));
            return;
        }
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get('vaultData');

        request.onsuccess = (event) => resolve(event.target.result);
        request.onerror = (event) => reject(event.target.error);
    });
}

// --- Authentication and Vault Management ---

/**
 * Sets up a new master password and initializes the vault.
 */
async function setupMasterPassword() {
    const masterPw = masterPasswordInput.value;
    const confirmPw = confirmMasterPasswordInput.value;

    if (!masterPw || !confirmPw) {
        showMessage('Please fill in both password fields.', 'error');
        return;
    }
    if (masterPw !== confirmPw) {
        showMessage('Passwords do not match.', 'error');
        return;
    }
    if (masterPw.length < 8) {
        showMessage('Master password must be at least 8 characters long.', 'error');
        return;
    }

    try {
        // Generate a salt for PBKDF2 for master password derivation
        const masterSalt = window.crypto.getRandomValues(new Uint8Array(16));
        const masterDerivedKey = await deriveKeyFromPassword(masterPw, masterSalt);

        // Generate the actual vault encryption key (VEK)
        vaultEncryptionKey = await generateAESKey();
        const exportedVek = await exportKey(vaultEncryptionKey);

        // Encrypt the VEK using the masterDerivedKey
        const vekIv = generateIv();
        const encryptedVek = await encryptData(exportedVek, masterDerivedKey, vekIv);

        // Prepare initial empty vault content
        vaultData = [];
        const vaultContentIv = generateIv();
        const encryptedVaultContent = await encryptData(JSON.stringify(vaultData), vaultEncryptionKey, vaultContentIv);

        // Store everything in IndexedDB
        await storeEncryptedVault({
            masterSalt: arrayBufferToBase64(masterSalt),
            encryptedVaultEncryptionKey: encryptedVek,
            vekIv: arrayBufferToBase64(vekIv),
            vaultContentIv: arrayBufferToBase64(vaultContentIv),
            encryptedVaultContent: encryptedVaultContent
        });

        isAuthenticated = true;
        showMessage('Master password set and vault initialized successfully!', 'success');
        updateUI();
        startAutolock();
    } catch (error) {
        console.error('Error setting up master password:', error);
        showMessage('Error setting up vault. Please try again.', 'error');
    }
}

/**
 * Attempts to unlock the vault with the provided master password.
 */
async function unlockVault() {
    const masterPw = masterPasswordInput.value;
    if (!masterPw) {
        showMessage('Please enter your master password.', 'error');
        return;
    }

    try {
        const storedVault = await getEncryptedVault();
        if (!storedVault) {
            showMessage('No vault found. Please set up a new master password.', 'error');
            // This scenario should be caught by initial check, but good to have.
            return;
        }

        const masterSalt = base64ToArrayBuffer(storedVault.masterSalt);
        const masterDerivedKey = await deriveKeyFromPassword(masterPw, masterSalt);

        // Decrypt the Vault Encryption Key (VEK)
        const vekIv = base64ToArrayBuffer(storedVault.vekIv);
        const exportedVek = await decryptData(storedVault.encryptedVaultEncryptionKey, masterDerivedKey, vekIv);
        vaultEncryptionKey = await importKey(exportedVek);

        // Decrypt the main vault content
        const vaultContentIv = base64ToArrayBuffer(storedVault.vaultContentIv);
        const decryptedVaultContent = await decryptData(storedVault.encryptedVaultContent, vaultEncryptionKey, vaultContentIv);
        vaultData = JSON.parse(decryptedVaultContent);

        isAuthenticated = true;
        showMessage('Vault unlocked successfully!', 'success');
        updateUI();
        startAutolock();
        renderVaultEntries();
    } catch (error) {
        console.error('Vault unlock failed:', error);
        showMessage('Incorrect master password or corrupted vault data.', 'error');
    }
}

/**
 * Locks the vault, clearing sensitive in-memory data and returning to auth screen.
 */
function lockVault() {
    isAuthenticated = false;
    vaultEncryptionKey = null;
    vaultData = []; // Clear decrypted data from memory
    clearTimeout(autolockTimer); // Stop the autolock timer
    passwordToUseInEntryModal = ''; // Clear any pending generated password

    // Clear password input fields for security
    masterPasswordInput.value = '';
    confirmMasterPasswordInput.value = '';
    entryPasswordInput.value = '';

    showMessage('Vault locked.', 'info');
    updateUI();
    renderVaultEntries(); // Clear displayed entries
}

/**
 * Starts the autolock timer, resetting it on user activity.
 */
function startAutolock() {
    clearTimeout(autolockTimer);
    autolockTimer = setTimeout(lockVault, AUTOLOCK_TIMEOUT);
}

/**
 * Resets the autolock timer on user interaction.
 */
function resetAutolockTimer() {
    if (isAuthenticated) {
        startAutolock();
    }
}

// Add event listeners for user activity to reset autolock
document.addEventListener('mousemove', resetAutolockTimer);
document.addEventListener('keydown', resetAutolockTimer);
document.addEventListener('click', resetAutolockTimer);
document.addEventListener('scroll', resetAutolockTimer);

/**
 * Saves the current state of vaultData (encrypted) to IndexedDB.
 */
async function saveVault() {
    if (!isAuthenticated || !vaultEncryptionKey) {
        console.warn('Cannot save vault: Not authenticated or key missing.');
        return;
    }
    try {
        const vaultContentIv = generateIv();
        const encryptedVaultContent = await encryptData(JSON.stringify(vaultData), vaultEncryptionKey, vaultContentIv);

        // Get the existing stored data to preserve masterSalt, encryptedVek, vekIv
        const storedVault = await getEncryptedVault();
        if (storedVault) {
            await storeEncryptedVault({
                ...storedVault, // Preserve master authentication details
                vaultContentIv: arrayBufferToBase64(vaultContentIv),
                encryptedVaultContent: encryptedVaultContent
            });
            showMessage('Vault saved successfully.', 'success');
        } else {
            console.error('Could not find existing vault structure to update.');
            showMessage('Error saving vault: Vault structure not found.', 'error');
        }
    } catch (error) {
        console.error('Error saving vault:', error);
        showMessage('Error saving vault data. Check console for details.', 'error');
    }
}

/**
 * Handles changing the master password.
 */
async function changeMasterPassword() {
    if (!isAuthenticated) {
        showMessage('Please unlock the vault first to change your master password.', 'info');
        changeMasterPasswordModal.classList.remove('active');
        return;
    }

    const currentPw = currentMasterPasswordInput.value;
    const newPw = newMasterPasswordInput.value;
    const confirmNewPw = confirmNewMasterPasswordInput.value;

    if (!currentPw || !newPw || !confirmNewPw) {
        showMessage('All fields are required to change the master password.', 'error');
        return;
    }
    if (newPw !== confirmNewPw) {
        showMessage('New passwords do not match.', 'error');
        return;
    }
    if (newPw.length < 8) {
        showMessage('New master password must be at least 8 characters long.', 'error');
        return;
    }
    if (currentPw === newPw) {
        showMessage('New password cannot be the same as the current password.', 'error');
        return;
    }

    try {
        const storedVault = await getEncryptedVault();
        if (!storedVault) {
            showMessage('Vault data not found. Cannot change password.', 'error');
            return;
        }

        // 1. Verify current master password by attempting to decrypt VEK
        const masterSalt = base64ToArrayBuffer(storedVault.masterSalt);
        const masterDerivedKey = await deriveKeyFromPassword(currentPw, masterSalt);
        
        // This will throw if the current password is incorrect, caught by outer try-catch
        const exportedVek = await decryptData(storedVault.encryptedVaultEncryptionKey, masterDerivedKey, base64ToArrayBuffer(storedVault.vekIv));
        // VEK is successfully decrypted in memory, confirming current password is correct.
        
        // 2. Generate a new master salt for the new master password
        const newMasterSalt = window.crypto.getRandomValues(new Uint8Array(16));
        const newMasterDerivedKey = await deriveKeyFromPassword(newPw, newMasterSalt);

        // 3. Re-encrypt the *original* (already decrypted and in memory) vaultEncryptionKey
        // using the new masterDerivedKey and a new IV for the VEK
        const newVekIv = generateIv();
        const newEncryptedVek = await encryptData(exportedVek, newMasterDerivedKey, newVekIv);

        // 4. Update IndexedDB with the new master authentication parameters
        await storeEncryptedVault({
            ...storedVault, // Keep existing vaultContentIv and encryptedVaultContent
            masterSalt: arrayBufferToBase64(newMasterSalt),
            encryptedVaultEncryptionKey: newEncryptedVek,
            vekIv: arrayBufferToBase64(newVekIv),
        });

        showMessage('Master password changed successfully! Vault will now relock.', 'success');
        changeMasterPasswordModal.classList.remove('active');
        // Force relock to ensure the new master password is used on next unlock
        lockVault();
    } catch (error) {
        console.error('Error changing master password:', error);
        if (error.message.includes('Decryption failed')) {
            showMessage('Incorrect current master password.', 'error');
        } else {
            showMessage('Failed to change master password. Please try again.', 'error');
        }
    } finally {
        // Clear all password fields in the modal for security
        currentMasterPasswordInput.value = '';
        newMasterPasswordInput.value = '';
        confirmNewMasterPasswordInput.value = '';
    }
}


// --- UI Rendering ---

/**
 * Updates the UI based on authentication status.
 */
async function updateUI() {
    if (loadingMessage) {
        loadingMessage.classList.add('hidden'); // Hide loading message
    }
    appContainer.classList.remove('hidden'); // Show the main app container

    if (isAuthenticated) {
        authScreen.classList.add('hidden');
        vaultView.classList.remove('hidden');
        lockButton.classList.remove('hidden');
        // Show change password button when authenticated
        if (changeMasterPasswordButton) {
            changeMasterPasswordButton.classList.remove('hidden');
        }
        statusIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-6 h-6 text-green-400">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 1 1 9 0v3.75M3.75 21V6.75a4.5 4.5 0 0 1 7.11-3.619M11.25 10.5V11.25m-4.5 8.25V12M12 21.75V15m-4.5 0V12m4.5 5.25v-4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                                </svg>`;
        statusText.textContent = 'Unlocked';
        // Clear auth screen inputs
        masterPasswordInput.value = '';
        confirmMasterPasswordInput.value = '';
    } else {
        authScreen.classList.remove('hidden');
        vaultView.classList.add('hidden');
        lockButton.classList.add('hidden');
        // Hide change password button when locked
        if (changeMasterPasswordButton) {
            changeMasterPasswordButton.classList.add('hidden');
        }
        statusIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-6 h-6 text-yellow-300">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                                </svg>`;
        statusText.textContent = 'Locked';

        const hasVaultData = await getEncryptedVault();
        if (hasVaultData) {
            authTitle.textContent = 'Unlock Vault';
            authDescription.textContent = 'Enter your master password to unlock your vault.';
            authButton.textContent = 'Unlock Vault';
            confirmPasswordGroup.classList.add('hidden'); // Hide confirm password field
            importExistingVaultButton.classList.add('hidden'); // Hide import button if vault exists
        } else {
            authTitle.textContent = 'Set Up Master Password';
            authDescription.textContent = 'Create a strong master password to secure your vault. This password will never be stored.';
            authButton.textContent = 'Set Master Password';
            confirmPasswordGroup.classList.remove('hidden'); // Show confirm password field
            importExistingVaultButton.classList.remove('hidden'); // Show import button if no vault exists
        }
    }
}

/**
 * Renders the vault entries in the UI, applying search filters.
 */
async function renderVaultEntries() {
    vaultList.innerHTML = ''; // Clear existing entries
    const searchTerm = searchVaultInput.value.toLowerCase();
    const filteredEntries = vaultData.filter(entry =>
        entry.url.toLowerCase().includes(searchTerm) ||
        entry.username.toLowerCase().includes(searchTerm) ||
        entry.notes.toLowerCase().includes(searchTerm)
    );

    if (filteredEntries.length === 0) {
        noEntriesMessage.classList.remove('hidden');
        if (searchTerm) {
            noEntriesMessage.textContent = 'No matching entries found.';
        } else {
            noEntriesMessage.textContent = 'No entries yet. Click "Add Entry" to get started!';
        }
    } else {
        noEntriesMessage.classList.add('hidden');
        for (const entry of filteredEntries) {
            const entryElement = document.createElement('div');
            entryElement.className = 'vault-entry p-4 bg-white rounded-lg shadow flex flex-col md:flex-row justify-between items-start md:items-center space-y-3 md:space-y-0';
            entryElement.innerHTML = `
                <div class="flex-1 min-w-0">
                    <p class="text-xl font-semibold text-blue-700 truncate">${entry.url}</p>
                    <p class="text-gray-700 truncate">Username: ${entry.username}</p>
                    <p class="text-gray-500 text-sm mt-1 break-words">${entry.notes ? 'Notes: ' + entry.notes : ''}</p>
                </div>
                <div class="flex flex-col md:flex-row space-y-2 md:space-y-0 md:space-x-2 w-full md:w-auto mt-3 md:mt-0">
                    <button data-id="${entry.id}" data-action="copy-username" class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-800 py-2 px-3 rounded-md text-sm font-medium transition duration-150 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4 mr-1">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 17.25v-3m-9 3l9 3V9m-9 3l9-3m-9 0V3m12 8.25V21m0-10.5V3m0 8.25H21M12 4.5H3m12 6H9" />
                        </svg>
                        Copy User
                    </button>
                    <button data-id="${entry.id}" data-action="copy-password" class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-800 py-2 px-3 rounded-md text-sm font-medium transition duration-150 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4 mr-1">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 17.25v-3.004m0 0l-1.427 1.427M15.75 14.246 17.173 15.67M18 19.5H6a2.25 2.25 0 0 1-2.25-2.25V6.75A2.25 2.25 0 0 1 6 4.5h11.25c.621 0 1.125.504 1.125 1.125V18a2.25 2.25 0 0 1-2.25 2.25Z" />
                        </svg>
                        Copy Pass
                    </button>
                    <button data-id="${entry.id}" data-action="edit" class="flex-1 bg-yellow-500 hover:bg-yellow-600 text-white py-2 px-3 rounded-md text-sm font-medium transition duration-150 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4 mr-1">
                            <path stroke-linecap="round" stroke-linejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14.25v4.5m-6.75-4.5H5.25" />
                        </svg>
                        Edit
                    </button>
                    <button data-id="${entry.id}" data-action="delete" class="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 px-3 rounded-md text-sm font-medium transition duration-150 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4 mr-1">
                            <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.925a2.25 2.25 0 0 1-2.244-2.077L4.747 5.996m14.86-3.21c.34-.058.678-.114 1.022-.165m-1.022.165 1.12-1.258m-1.12 1.258A9 9 0 1 1 2.75 10.5M12 10.5v6" />
                        </svg>
                        Delete
                    </button>
                </div>
            `;
            vaultList.appendChild(entryElement);
        }
    }
}

/**
 * Handles clicks on vault entry action buttons (copy, edit, delete).
 * @param {Event} event The click event.
 */
async function handleVaultEntryAction(event) {
    const button = event.target.closest('button[data-action]');
    if (!button) return;

    const id = button.dataset.id;
    const action = button.dataset.action;
    const entry = vaultData.find(e => e.id === id);

    if (!entry) {
        showMessage('Entry not found!', 'error');
        return;
    }

    try {
        switch (action) {
            case 'copy-username':
                await copyToClipboard(entry.username);
                break;
            case 'copy-password':
                const decryptedPassword = await decryptData(entry.encryptedPassword, vaultEncryptionKey, base64ToArrayBuffer(entry.passwordIv));
                await copyToClipboard(decryptedPassword);
                break;
            case 'edit':
                currentEditEntryId = id;
                entryModalTitle.textContent = 'Edit Entry';
                entryForm.reset(); // Clear form fields
                entryUrlInput.value = entry.url;
                entryUsernameInput.value = entry.username;
                // Decrypt password for editing (temporarily)
                const decryptedPass = await decryptData(entry.encryptedPassword, vaultEncryptionKey, base64ToArrayBuffer(entry.passwordIv));
                entryPasswordInput.value = decryptedPass;
                entryNotesInput.value = entry.notes;
                entryModal.classList.add('active');
                break;
            case 'delete':
                // Use custom confirmation instead of browser's confirm()
                confirmDeleteModal.classList.add('active');
                confirmDeleteButton.onclick = async () => {
                    vaultData = vaultData.filter(e => e.id !== id);
                    await saveVault();
                    renderVaultEntries();
                    showMessage('Entry deleted successfully.', 'success');
                    confirmDeleteModal.classList.remove('active');
                };
                break;
        }
    } catch (error) {
        console.error('Error performing entry action:', error);
        showMessage(`Failed to ${action} entry.`, 'error');
    }
}

/**
 * Generates a random password based on selected options.
 * @returns {string} The generated password.
 */
function generatePassword() {
    const length = parseInt(passwordLengthInput.value, 10);
    let charset = '';
    if (includeLowercaseCheckbox.checked) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (includeUppercaseCheckbox.checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeNumbersCheckbox.checked) charset += '0123456789';
    if (includeSymbolsCheckbox.checked) charset += '!@#$%^&*()-_+=[]{}|;:,.<>?';

    if (charset.length === 0) {
        showMessage('Please select at least one character type.', 'error');
        return '';
    }

    let password = '';
    const randomBytes = new Uint32Array(length);
    window.crypto.getRandomValues(randomBytes);

    for (let i = 0; i < length; i++) {
        password += charset[randomBytes[i] % charset.length];
    }

    return password;
}

/**
 * Evaluates and displays the strength of a given password.
 * This is a simple heuristic and not a cryptographically strong strength checker.
 * @param {string} password The password to evaluate.
 */
function evaluatePasswordStrength(password) {
    let strength = 0;
    const feedback = [];

    // Length
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (password.length >= 16) strength += 1;

    // Character types
    if (/[a-z]/.test(password)) strength += 1; // Lowercase
    if (/[A-Z]/.test(password)) strength += 1; // Uppercase
    if (/[0-9]/.test(password)) strength += 1; // Numbers
    if (/[!@#$%^&*()-_+=[]{}\|;:,.<>?]/.test(password)) strength += 1; // Symbols

    // Avoid common patterns (very basic)
    if (/(.)\1\1/.test(password)) feedback.push('Avoid repeating characters.'); // e.g., aaa
    if (/123|abc/.test(password.toLowerCase())) feedback.push('Avoid common sequences.');

    let strengthText = '';
    let textColor = '';

    if (strength <= 3) {
        strengthText = 'Weak';
        textColor = 'text-red-600';
    } else if (strength <= 5) {
        strengthText = 'Moderate';
        textColor = 'text-yellow-600';
    } else if (strength <= 7) {
        strengthText = 'Strong';
        textColor = 'text-blue-600';
    } else {
        strengthText = 'Very Strong';
        textColor = 'text-green-600';
    }

    generatedPasswordStrength.className = `text-sm mt-2 font-medium ${textColor}`;
    generatedPasswordStrength.textContent = `Strength: ${strengthText}${feedback.length > 0 ? ' (' + feedback.join(' ') + ')' : ''}`;
}

// --- Event Listeners ---

// Auth screen buttons
authButton.addEventListener('click', async () => {
    try {
        const hasVaultData = await getEncryptedVault();
        if (hasVaultData) {
            unlockVault();
        } else {
            setupMasterPassword();
        }
    } catch (error) {
        console.error('Error on auth button click:', error);
        showMessage('An unexpected error occurred during authentication. Check console for details.', 'error');
    }
});

lockButton.addEventListener('click', lockVault);

// Vault actions
addEntryButton.addEventListener('click', () => {
    console.log('Add Entry button clicked. Opening modal.'); // Debugging log
    currentEditEntryId = null; // Clear edit state
    entryModalTitle.textContent = 'Add New Entry';
    entryForm.reset(); // Clear form fields
    if (passwordToUseInEntryModal) {
        entryPasswordInput.value = passwordToUseInEntryModal;
        passwordToUseInEntryModal = ''; // Clear after use
    }
    entryModal.classList.add('active');
});

vaultList.addEventListener('click', handleVaultEntryAction);

searchVaultInput.addEventListener('input', renderVaultEntries);

// Entry Modal buttons
cancelEntryButton.addEventListener('click', () => {
    console.log('Cancel Entry button clicked. Closing modal.'); // Debugging log
    entryModal.classList.remove('active');
});

entryForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    console.log('Entry form submitted.'); // Debugging log
    console.log('isAuthenticated:', isAuthenticated); // Debugging log
    console.log('vaultEncryptionKey:', vaultEncryptionKey); // Debugging log

    if (!isAuthenticated || !vaultEncryptionKey) {
        showMessage('Vault not unlocked. Please unlock first.', 'error');
        entryModal.classList.remove('active');
        console.error('Form submission blocked: Not authenticated or encryption key missing.'); // Debugging log
        return;
    }

    const url = entryUrlInput.value.trim();
    const username = entryUsernameInput.value.trim();
    const password = entryPasswordInput.value; // Keep raw for encryption
    const notes = entryNotesInput.value.trim();

    console.log('Form data captured:', { url, username, password: '***', notes }); // Debugging log (password masked)

    try {
        const passwordIv = generateIv();
        console.log('Generated IV for password encryption.'); // Debugging log
        const encryptedPassword = await encryptData(password, vaultEncryptionKey, passwordIv);
        console.log('Password encrypted successfully.'); // Debugging log

        if (currentEditEntryId) {
            // Edit existing entry
            vaultData = vaultData.map(entry => {
                if (entry.id === currentEditEntryId) {
                    return {
                        id: entry.id,
                        url,
                        username,
                        encryptedPassword,
                        passwordIv: arrayBufferToBase64(passwordIv),
                        notes
                    };
                }
                return entry;
            });
            showMessage('Entry updated successfully!', 'success');
            console.log('Vault entry updated.'); // Debugging log
        } else {
            // Add new entry
            const newEntry = {
                id: crypto.randomUUID(), // Unique ID for each entry
                url,
                username,
                encryptedPassword,
                passwordIv: arrayBufferToBase64(passwordIv),
                notes
            };
            vaultData.push(newEntry);
            showMessage('Entry added successfully!', 'success');
            console.log('New vault entry added.'); // Debugging log
        }

        await saveVault();
        console.log('Vault data saved to IndexedDB.'); // Debugging log
        renderVaultEntries();
        console.log('Vault entries re-rendered.'); // Debugging log
        entryModal.classList.remove('active');
        console.log('Entry modal closed.'); // Debugging log
    } catch (error) {
        console.error('Error during entry save process:', error); // More specific error log
        showMessage('Failed to save entry. Encryption or storage error.', 'error');
    }
});

toggleEntryPasswordVisibility.addEventListener('click', () => {
    const type = entryPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    entryPasswordInput.setAttribute('type', type);
    // You could also change the icon here
});

// Password Generator Modal buttons
generatePasswordButton.addEventListener('click', () => {
    console.log('Generate Password button clicked. Opening generator modal.'); // Debugging log
    generatorModal.classList.add('active');
    // Generate initial password on modal open
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});

cancelGeneratorButton.addEventListener('click', () => {
    console.log('Cancel Generator button clicked. Closing generator modal.'); // Debugging log
    generatorModal.classList.remove('active');
});

generateNewPasswordButton.addEventListener('click', () => {
    console.log('Generate New Password button clicked.'); // Debugging log
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});

copyGeneratedPasswordButton.addEventListener('click', () => {
    console.log('Copy Generated Password button clicked.'); // Debugging log
    const pass = generatedPasswordDisplay.value;
    if (pass) {
        copyToClipboard(pass);
    }
});

useGeneratedPasswordButton.addEventListener('click', () => {
    console.log('Use Generated Password button clicked.'); // Debugging log
    passwordToUseInEntryModal = generatedPasswordDisplay.value;
    generatorModal.classList.remove('active');
    // If add/edit modal is not open, open it
    if (!entryModal.classList.contains('active')) {
        addEntryButton.click(); // Simulate click on Add Entry to open and pre-fill
    } else {
        entryPasswordInput.value = passwordToUseInEntryModal;
    }
});

passwordLengthInput.addEventListener('input', () => {
    lengthValueSpan.textContent = passwordLengthInput.value;
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});

// Re-generate password when character options change
includeUppercaseCheckbox.addEventListener('change', () => {
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});
includeLowercaseCheckbox.addEventListener('change', () => {
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});
includeNumbersCheckbox.addEventListener('change', () => {
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});
includeSymbolsCheckbox.addEventListener('change', () => {
    const newPass = generatePassword();
    generatedPasswordDisplay.value = newPass;
    evaluatePasswordStrength(newPass);
});


// Confirm Delete Modal buttons
cancelDeleteButton.addEventListener('click', () => confirmDeleteModal.classList.remove('active'));

// Import/Export functionality
exportVaultButton.addEventListener('click', async () => {
    try {
        const storedVault = await getEncryptedVault();
        if (!storedVault) {
            showMessage('No vault data to export.', 'info');
            return;
        }

        // We export the entirely encrypted vault data as stored in IndexedDB
        const blob = new Blob([JSON.stringify(storedVault, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'secure_vault_backup_encrypted.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showMessage('Vault data exported successfully (encrypted).', 'success');
    } catch (error) {
        console.error('Error exporting vault:', error);
        showMessage('Failed to export vault data.', 'error');
    }
});

triggerImportVaultButton.addEventListener('click', () => {
    importVaultFileInput.click(); // Trigger the hidden file input
});

importVaultFileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) {
        return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const importedData = JSON.parse(e.target.result);

            // Basic validation for required fields in imported data
            if (!importedData.masterSalt || !importedData.encryptedVaultEncryptionKey ||
                !importedData.vekIv || !importedData.vaultContentIv || !importedData.encryptedVaultContent) {
                showMessage('Invalid vault file format.', 'error');
                return;
            }

            // Custom confirmation dialog
            const confirmationModal = document.createElement('div');
            confirmationModal.className = 'modal-overlay active';
            confirmationModal.innerHTML = `
                <div class="modal-content max-w-sm">
                    <h2 class="text-xl font-semibold text-gray-800 mb-4 text-center">Import Vault</h2>
                    <p class="text-gray-700 text-center mb-6">Enter your master password to import the vault. This is required to decrypt and re-encrypt the data with your current vault settings.</p>
                    <input type="password" id="import-master-password" class="w-full p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 mb-4" placeholder="Enter your master password">
                    <p id="import-modal-error" class="text-red-600 text-sm mb-4 hidden"></p>
                    <div class="flex justify-center space-x-4">
                        <button type="button" id="cancel-import-confirm" class="px-5 py-2 rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50">Cancel</button>
                        <button type="button" id="confirm-import-proceed" class="px-5 py-2 rounded-md bg-blue-600 text-white font-semibold hover:bg-blue-700">Import</button>
                    </div>
                </div>
            `;
            document.body.appendChild(confirmationModal);

            const importMasterPasswordInput = document.getElementById('import-master-password');
            const importModalError = document.getElementById('import-modal-error');
            const cancelImportConfirmButton = document.getElementById('cancel-import-confirm');
            const confirmImportProceedButton = document.getElementById('confirm-import-proceed');

            cancelImportConfirmButton.addEventListener('click', () => {
                confirmationModal.remove();
                showMessage('Import cancelled.', 'info');
                event.target.value = ''; // Clear file input
            });

            confirmImportProceedButton.addEventListener('click', async () => {
                const userMasterPassword = importMasterPasswordInput.value;
                if (!userMasterPassword) {
                    importModalError.textContent = 'Master password is required.';
                    importModalError.classList.remove('hidden');
                    return;
                }
                importModalError.classList.add('hidden'); // Clear previous error

                try {
                    // Attempt to decrypt the imported data's VEK with the provided master password
                    const importedMasterSalt = base64ToArrayBuffer(importedData.masterSalt);
                    const importedMasterDerivedKey = await deriveKeyFromPassword(userMasterPassword, importedMasterSalt);

                    const importedVekIv = base64ToArrayBuffer(importedData.vekIv);
                    const importedExportedVek = await decryptData(importedData.encryptedVaultEncryptionKey, importedMasterDerivedKey, importedVekIv);
                    const importedVek = await importKey(importedExportedVek);

                    // Decrypt the imported vault content
                    const importedVaultContentIv = base64ToArrayBuffer(importedData.vaultContentIv);
                    const decryptedImportedVaultContent = await decryptData(importedData.encryptedVaultContent, importedVek, importedVaultContentIv);
                    const newVaultEntries = JSON.parse(decryptedImportedVaultContent);

                    // Check if there's an existing vault
                    const existingVault = await getEncryptedVault();
                    if (existingVault) {
                        // Use custom confirmation for overwrite
                        const overwriteConfirmationModal = document.createElement('div');
                        overwriteConfirmationModal.className = 'modal-overlay active';
                        overwriteConfirmationModal.innerHTML = `
                            <div class="modal-content max-w-sm">
                                <h2 class="text-xl font-semibold text-gray-800 mb-4 text-center">Overwrite Existing Vault?</h2>
                                <p class="text-gray-700 text-center mb-6">An existing vault is detected. Do you want to overwrite it with the imported data? This action cannot be undone.</p>
                                <div class="flex justify-center space-x-4">
                                    <button type="button" id="cancel-overwrite-confirm" class="px-5 py-2 rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50">Cancel</button>
                                    <button type="button" id="confirm-overwrite-proceed" class="px-5 py-2 rounded-md bg-red-600 text-white font-semibold hover:bg-red-700">Overwrite</button>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(overwriteConfirmationModal);

                        const cancelOverwriteConfirmButton = document.getElementById('cancel-overwrite-confirm');
                        const confirmOverwriteProceedButton = document.getElementById('confirm-overwrite-proceed');

                        cancelOverwriteConfirmButton.addEventListener('click', () => {
                            overwriteConfirmationModal.remove();
                            confirmationModal.remove();
                            showMessage('Import cancelled.', 'info');
                            event.target.value = ''; // Clear file input
                        });

                        confirmOverwriteProceedButton.addEventListener('click', async () => {
                            overwriteConfirmationModal.remove();
                            await processImport(newVaultEntries, userMasterPassword, existingVault, importedData); // Pass importedData
                            confirmationModal.remove();
                            event.target.value = ''; // Clear file input
                        });
                    } else {
                        await processImport(newVaultEntries, userMasterPassword, existingVault, importedData); // Pass importedData
                        confirmationModal.remove();
                        event.target.value = ''; // Clear file input
                    }

                } catch (error) {
                    console.error('Error during import process:', error);
                    importModalError.textContent = 'Incorrect master password or corrupted import file.';
                    importModalError.classList.remove('hidden');
                }
            });
        } catch (error) {
            console.error('Error reading or parsing import file:', error);
            showMessage('Failed to read or parse import file. It might be corrupted or not a valid JSON.', 'error');
            event.target.value = ''; // Clear file input
        }
    };
    reader.readAsText(file);
});


// Helper function to finalize the import process after confirmations
async function processImport(newVaultEntries, userMasterPassword, existingVault, importedRawData) {
    let finalEncryptedContent;
    let finalContentIv;
    let finalMasterSalt;
    let finalEncryptedVek;
    let finalVekIv;

    if (isAuthenticated && vaultEncryptionKey) {
        // Scenario 1: User is already authenticated and importing into an open vault.
        // Re-encrypt the imported data using the *current* active vault encryption key
        finalContentIv = generateIv();
        finalEncryptedContent = await encryptData(JSON.stringify(newVaultEntries), vaultEncryptionKey, finalContentIv);

        // Retain the current vault's master security parameters
        finalMasterSalt = existingVault.masterSalt;
        finalEncryptedVek = existingVault.encryptedVaultEncryptionKey;
        finalVekIv = existingVault.vekIv;

        // Update the in-memory vault data
        vaultData = newVaultEntries;

    } else {
        // Scenario 2: User is importing into a locked/empty vault (initial setup or overwrite when locked).
        // The master salt and encrypted VEK for the *newly active vault* should come from the imported data.
        // The user's input master password was already used to decrypt the imported VEK.
        finalMasterSalt = importedRawData.masterSalt; // Use the master salt from the imported file
        finalEncryptedVek = importedRawData.encryptedVaultEncryptionKey; // Use the encrypted VEK from the imported file
        finalVekIv = importedRawData.vekIv; // Use the VEK IV from the imported file

        // The vaultEncryptionKey for the current session should be the one we just successfully decrypted from the imported file
        // Re-derive the VEK using the imported master salt and user's entered password to set it for the session
        const masterDerivedKeyForImportedVek = await deriveKeyFromPassword(userMasterPassword, base64ToArrayBuffer(finalMasterSalt));
        const importedExportedVek = await decryptData(finalEncryptedVek, masterDerivedKeyForImportedVek, base64ToArrayBuffer(finalVekIv));
        vaultEncryptionKey = await importKey(importedExportedVek);


        // Encrypt the imported vault content using this importedVek (which is now vaultEncryptionKey)
        finalContentIv = generateIv();
        finalEncryptedContent = await encryptData(JSON.stringify(newVaultEntries), vaultEncryptionKey, finalContentIv);

        // Set authentication to true for the current session and update in-memory data
        isAuthenticated = true;
        vaultData = newVaultEntries;
        startAutolock();
    }

    // Store the updated/re-encrypted vault data in IndexedDB
    await storeEncryptedVault({
        id: 'vaultData',
        masterSalt: finalMasterSalt, // This is already a Base64 string from importedRawData
        encryptedVaultEncryptionKey: finalEncryptedVek, // This is already a Base64 string from importedRawData
        vekIv: finalVekIv, // This is already a Base64 string from importedRawData
        vaultContentIv: arrayBufferToBase64(finalContentIv),
        encryptedVaultContent: finalEncryptedContent
    });

    showMessage('Vault imported and re-encrypted successfully!', 'success');
    renderVaultEntries();
    updateUI(); // Re-render UI to unlocked state if applicable
}


importExistingVaultButton.addEventListener('click', () => {
    importVaultFileInput.click(); // Trigger the hidden file input
});

// Event Listener for Change Master Password button
changeMasterPasswordButton.addEventListener('click', () => {
    if (!isAuthenticated) {
        showMessage('Please unlock the vault first to change your master password.', 'info');
        return;
    }
    // Clear any previous values in the change password modal
    currentMasterPasswordInput.value = '';
    newMasterPasswordInput.value = '';
    confirmNewMasterPasswordInput.value = '';
    changeMasterPasswordModal.classList.add('active');
});

// Event Listeners for Change Master Password Modal
cancelChangePasswordButton.addEventListener('click', () => {
    changeMasterPasswordModal.classList.remove('active');
    // Clear fields on cancel
    currentMasterPasswordInput.value = '';
    newMasterPasswordInput.value = '';
    confirmNewMasterPasswordInput.value = '';
});

saveNewMasterPasswordButton.addEventListener('click', changeMasterPassword);


// --- Initialization ---

window.onload = async () => {
    try {
        // Hide loading message and show app container on successful initialization
        if (loadingMessage) {
            loadingMessage.classList.add('hidden');
        }
        appContainer.classList.remove('hidden');

        db = await initDb();
        const storedVault = await getEncryptedVault();
        if (storedVault) {
            // Vault exists, show unlock screen
            updateUI();
        } else {
            // No vault, show setup screen
            updateUI();
        }
    } catch (error) {
        // Catch IndexedDB initialization errors specifically
        console.error('Initialization failed:', error);
        showGlobalError(`Application failed to initialize: ${error.message}.`);
    }
};

