const { Keypair } = solanaWeb3;

// UI elements
const output = document.getElementById('output');
const decOutput = document.getElementById('decOutput');
const prefixInput = document.getElementById('prefix');
const passwordInput = document.getElementById('password');
const encInput = document.getElementById('encKey');
const decPasswordInput = document.getElementById('decPassword');
const generateBtn = document.getElementById('generateBtn');
const copyBtn = document.getElementById('copyBtn');
const decryptBtn = document.getElementById('decryptBtn');

copyBtn.style.display = 'none';
let currentEncryptedKey = null;
let currentPublicKey = null;

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(buffer) {
    let intVal = BigInt('0x' + Array.from(buffer).map(b => b.toString(16).padStart(2,'0')).join(''));
    let result = '';
    while(intVal > 0) {
        const mod = intVal % 58n;
        intVal = intVal / 58n;
        result = ALPHABET[Number(mod)] + result;
    }
    for (let i=0; i<buffer.length && buffer[i]===0; i++) result='1'+result;
    return result;
}

async function encryptSecret(secretBytes, password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey({
        name:"PBKDF2",
        salt: enc.encode("solana-salt"),
        iterations:100000,
        hash:"SHA-256"
    }, keyMaterial, {name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, secretBytes);


    const combined = new Uint8Array(iv.length + cipher.byteLength);
    combined.set(iv,0);
    combined.set(new Uint8Array(cipher), iv.length);

    return btoa(String.fromCharCode(...combined));
}

async function decryptSecret(encryptedBase64, password) {
    const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const iv = combined.slice(0,12);
    const cipher = combined.slice(12);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey({
        name:"PBKDF2",
        salt: enc.encode("solana-salt"),
        iterations:100000,
        hash:"SHA-256"
    }, keyMaterial, {name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);

    const decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, cipher);
    return new Uint8Array(decrypted);
}


generateBtn.onclick = async () => {
    const prefix = prefixInput.value.trim();
    const password = passwordInput.value;

    copyBtn.style.display = 'none';
    currentEncryptedKey = null;
    output.textContent = '';

    if (!prefix || prefix.length > 4) {
        output.textContent = "Invalid prefix (max 4 chars).";
        return;
    }

    output.textContent = `Generating key that starts with: ${prefix}...`;

    let kp, tries = 0;
    while(true){
        kp = Keypair.generate();
        tries++;
        if(kp.publicKey.toBase58().startsWith(prefix)) break;
        if(tries % 5000 === 0){
            output.textContent = `Generating key that starts with: ${prefix}...\nTries: ${tries}`;
            await new Promise(res=>setTimeout(res,1));
        }
    }

    currentEncryptedKey = await encryptSecret(kp.secretKey, password);
    currentPublicKey = kp.publicKey.toBase58();

    output.innerHTML = `Public Key: <strong>${currentPublicKey}</strong><br>Key generated in ${tries} tries.`;
    copyBtn.style.display = 'inline-block';
};


copyBtn.onclick = () => {
    if(currentEncryptedKey) navigator.clipboard.writeText(currentEncryptedKey).then(()=>alert("Copied!"));
};

decryptBtn.onclick = async () => {
    const encryptedInput = encInput.value.trim();
    const password = decPasswordInput.value.trim();

    decOutput.textContent = '';
    if(!encryptedInput) { decOutput.textContent = "Enter encrypted key"; return; }

    try {
        const secretKeyArray = await decryptSecret(encryptedInput, password);
        const base58Key = base58Encode(secretKeyArray);

        decOutput.innerHTML = `<strong>Base58 Private Key:</strong><br>${base58Key}<br><button id="copyBase58Btn">Copy</button>`;
        document.getElementById('copyBase58Btn').onclick = () => navigator.clipboard.writeText(base58Key).then(()=>alert("Copied!"));
    } catch(e){
        decOutput.textContent = 'Decryption failed! Wrong password?';
    }
};