const API_BASE = 'http://127.0.0.1:5000';

let currentUsername = '';
let currentChallenge = '';
let currentSalt = '';

// Helper to show messages
function showMsg(text, type = 'success') {
    const msgDiv = document.getElementById('message');
    msgDiv.textContent = text;
    msgDiv.className = `message show ${type}`;
    setTimeout(() => msgDiv.classList.remove('show'), 5000);
}

function addLog(label, value) {
    const logContainer = document.getElementById('challenge-log-container');
    logContainer.classList.remove('hidden');
    const logDiv = document.getElementById('challenge-log');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `<span class="label">[${label}]</span> <span class="value">${value}</span>`;
    logDiv.prepend(entry);
}

// SHA256 Helper
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Navigation
function showSection(id) {
    document.querySelectorAll('.form-section').forEach(s => s.classList.add('hidden'));
    document.getElementById(id).classList.remove('hidden');
}

function showLogin() { showSection('login-step1'); }
function showRegister() { showSection('register-section'); }

// Registration
async function register() {
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    if (!username || !password || !email) return showMsg('Please fill all fields', 'error');

    addLog('REG', `Registering user: ${username} with email: ${email}`);

    try {
        const res = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        const data = await res.json();
        if (res.ok) {
            showMsg(data.message);
            showLogin();
        } else {
            showMsg(data.message, 'error');
        }
    } catch (e) {
        showMsg('Server connection failed', 'error');
    }
}

// Step 1: Get Challenge
async function getChallenge() {
    currentUsername = document.getElementById('login-username').value;
    if (!currentUsername) return showMsg('Enter username', 'error');

    addLog('AUTH', `Requesting challenge for: ${currentUsername}`);

    try {
        const res = await fetch(`${API_BASE}/login-challenge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUsername })
        });
        const data = await res.json();
        if (res.ok) {
            currentChallenge = data.challenge;
            currentSalt = data.salt;
            addLog('CHALLENGE', `Received Nonce: ${currentChallenge}`);
            addLog('CHALLENGE', `Received User Salt: ${currentSalt}`);
            document.getElementById('challenge-display').textContent = currentChallenge.substring(0, 10) + '...';
            showSection('login-step2');
        } else {
            showMsg(data.message, 'error');
        }
    } catch (e) {
        showMsg('Server connection failed', 'error');
    }
}

// Step 2: Submit Challenge Response
async function submitResponse() {
    const password = document.getElementById('login-password').value;
    if (!password) return showMsg('Enter password', 'error');

    // Logic: Response = SHA256( SHA256(password + salt) + challenge )
    addLog('CRYPTO', `Computing salted secret: SHA256(password + salt)`);
    const secret = await sha256(password + currentSalt);
    addLog('CRYPTO', `Salted Secret: ${secret}`);
    
    addLog('CRYPTO', `Computing response: SHA256(secret + challenge)`);
    const response = await sha256(secret + currentChallenge);
    addLog('RESPONSE', `Derived Key: ${response}`);

    try {
        const res = await fetch(`${API_BASE}/login-verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                username: currentUsername,
                challenge: currentChallenge,
                response: response
            })
        });
        const data = await res.json();
        if (res.ok) {
            showMsg(data.message);
            addLog('SERVER', data.message);
            
            // Transition to OTP section if sent successfully
            if (data.status === 'otp_sent') {
                showSection('login-otp');
                if (data.email_status) {
                    addLog('OTP', `Email Handshake: ${data.email_status}`);
                }
            }
        } else {
            showMsg(data.message, 'error');
        }
    } catch (e) {
        showMsg('Verification failed', 'error');
    }
}

// Step 3: Verify OTP
async function verifyOTP() {
    const otp = document.getElementById('otp-code').value;
    if (otp.length !== 6) return showMsg('Enter 6-digit OTP', 'error');

    try {
        const res = await fetch(`${API_BASE}/verify-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                username: currentUsername,
                otp: otp
            })
        });
        const data = await res.json();
        if (res.ok) {
            showMsg(data.message);
            addLog('SESSION', `JWT Token Received: ${data.token.substring(0, 20)}...`);
            document.getElementById('jwt-token-display').textContent = data.token;
            showSection('success-section');
        } else {
            showMsg(data.message, 'error');
        }
    } catch (e) {
        showMsg('OTP failed', 'error');
    }
}

function reset() {
    location.reload();
}
