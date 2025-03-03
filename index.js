const { KeyEncapsulation, KEMs } = require("./liboqs-node/lib/index.js");

// Helper function to get the enabled algorithm
function getEnabledAlgorithm() {
  const algorithms = KEMs.getEnabledAlgorithms();
  return algorithms[0]; // Defaulting to the first enabled algorithm
}
let global_ciphertext = null;
async function generateKeypair() {
  const algorithm = getEnabledAlgorithm();
  const keyEncapsulation = new KeyEncapsulation(algorithm);

  const keypair = await keyEncapsulation.generateKeypair();
  const algorithmDetails = keyEncapsulation.getDetails();
  const publicKeyLength = algorithmDetails.publicKeyLength;
  const privateKeyLength = algorithmDetails.secretKeyLength;


  const publicKey = keypair.slice(0, publicKeyLength);
  const privateKey = keyEncapsulation.exportSecretKey();
  console.log(privateKey.length);
  return { publicKey, privateKey };
}

const crypto = require('crypto');

// Padding function (PKCS7 Padding)
function pad(data, blockSize) {
  const padding = blockSize - (data.length % blockSize);
  const paddingBuffer = Buffer.alloc(padding, padding);
  return Buffer.concat([data, paddingBuffer]);
}

// Unpadding function (removes the padding after decryption)
function unpad(data) {
  const paddingLength = data[data.length - 1];
  return data.slice(0, data.length - paddingLength);
}

async function encrypt(publicKey, text_to_encrypt) {
  const algorithm = getEnabledAlgorithm();
  const keyEncapsulation = new KeyEncapsulation(algorithm);

  const encapsulation = await keyEncapsulation.encapsulateSecret(publicKey);
  console.log('Encapsulation:', encapsulation);
  const secretKey = encapsulation.sharedSecret;
  global_ciphertext = encapsulation.ciphertext;
  // Hash the secret key to get 32 bytes (256 bits) if it's not of the correct length
  const derivedKey = crypto.createHash('sha256').update(secretKey).digest();

  const iv = crypto.randomBytes(16);  // Random 16-byte IV for AES CBC mode
  
  // Apply padding before encryption
  const paddedMessage = pad(Buffer.from(text_to_encrypt, 'utf8'), 16);
  
  const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
  let encrypted = cipher.update(paddedMessage);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  // Return both the IV and the encrypted message
  return Buffer.concat([iv, encrypted]);
}

// Debugging in decrypt
async function decrypt(encrypted_data, privateKey) {
  const algorithm = getEnabledAlgorithm();
  const keyEncapsulation = new KeyEncapsulation(algorithm, privateKey);

  const encrypted_buffer = Buffer.from(encrypted_data, 'hex');
  
  // Debugging: log the full encrypted buffer
  console.log('Encrypted Buffer:', encrypted_buffer.toString('hex'));

  const secret = await keyEncapsulation.decapsulateSecret(global_ciphertext);

  const derivedKey = crypto.createHash('sha256').update(secret).digest();

  const iv = encrypted_buffer.slice(0, 16);
  const ciphertext = encrypted_buffer.slice(16);

  // Debugging: log the IV, derived key, and ciphertext
  console.log('IV:', iv.toString('hex'));
  console.log('Derived Key:', derivedKey.toString('hex'));
  console.log('Ciphertext:', ciphertext.toString('hex'));

  const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);

  try {
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const unpadded = unpad(decrypted);

    // Debugging: log the unpadded decrypted message
    console.log('Decrypted Message (unpadded):', unpadded.toString('utf8'));

    return unpadded.toString('utf8');
  } catch (error) {
    console.error('Error during decryption:', error.message);
    throw new Error('Decryption failed');
  }
}



// Example usage of key generation, encryption, and decryption
async function example() {
  // Step 1: Key generation (creating an instance of KeyEncapsulation)
  const keypair = await generateKeypair();
   
  const text_to_encrypt = "text to encrypt with public key 30+ chars";
  
  // Step 2: Encryption (using the public key from the generated keypair)
  const encryptionResult = await encrypt(keypair.publicKey, text_to_encrypt);
  console.log("Encrypted message:", encryptionResult);
  
  // Step 3: Decryption (using the private key from the generated keypair)
  const decryptedMessage = await decrypt(encryptionResult, keypair.privateKey);
  console.log("Decrypted message:", decryptedMessage);
}

example();

