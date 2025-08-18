// mini-pki.js
const crypto = require("crypto");
const selfsigned = require("selfsigned");

// 1) Create a user identity: RSA private key + self-signed X.509 cert (public key inside)
function createIdentity(commonName = "user") {
  const { private: privateKeyPem, cert: certPem } = selfsigned.generate(
    [{ name: "commonName", value: commonName }],
    { keySize: 2048, days: 365, algorithm: "sha256" }
  );
  // Store these in your DB (privateKeyPem must be protected!)
  return { privateKeyPem, certPem };
}

// 2) Encrypt for recipient (hybrid: AES-256-GCM + RSA-OAEP-SHA256)
function encryptFor(recipientCertPem, plaintext, aad = null) {
  // extract public key from cert
  const pubKey = new crypto.X509Certificate(recipientCertPem).publicKey;

  // fresh AES session key + IV
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  // wrap AES key with RSA-OAEP (SHA-256)
  const encKey = crypto.publicEncrypt(
    { key: pubKey, oaepHash: "sha256" },
    aesKey
  );

  // JSON-safe bundle to send/store
  return {
    alg: "RSA-OAEP-256+AES-256-GCM",
    iv_b64: iv.toString("base64"),
    tag_b64: tag.toString("base64"),
    enc_key_b64: encKey.toString("base64"),
    ct_b64: ct.toString("base64"),
    aad: aad || null,
  };
}

// 3) Decrypt with recipient’s private key
function decryptFrom(myPrivateKeyPem, bundle) {
  const { iv_b64, tag_b64, enc_key_b64, ct_b64, aad } = bundle;

  // unwrap AES key
  const aesKey = crypto.privateDecrypt(
    { key: myPrivateKeyPem, oaepHash: "sha256" },
    Buffer.from(enc_key_b64, "base64")
  );

  // AES-GCM decrypt
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    aesKey,
    Buffer.from(iv_b64, "base64")
  );
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag_b64, "base64"));
  const pt = Buffer.concat([decipher.update(Buffer.from(ct_b64, "base64")), decipher.final()]);
  return pt.toString("utf8");
}

// ===== Example usage =====
// const { privateKeyPem, certPem } = createIdentity("levi@n11.dev");
// const message = encryptFor(certPem_of_recipient, "hello");
// const plaintext = decryptFrom(privateKeyPem_of_recipient, message);

function toPkcs8Pem(pkcs1Pem, passphrase) {
  // If it's already PKCS#8, return as-is
  if (pkcs1Pem.includes('BEGIN PRIVATE KEY')) return pkcs1Pem;

  const keyObj = crypto.createPrivateKey({
    key: pkcs1Pem,
    format: 'pem',
    passphrase, // omit if not encrypted
  });

  // Unencrypted PKCS#8 PEM (required for WebCrypto import)
  return keyObj.export({ type: 'pkcs8', format: 'pem' });
}

module.exports = { createIdentity, encryptFor, decryptFrom, toPkcs8Pem };
