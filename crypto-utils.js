const crypto = require('crypto');

const deriveKey = (password, salt) =>
  crypto.pbkdf2Sync(password, salt, 200_000, 32, 'sha256');

const encryptJSON = (key, data) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const json = Buffer.from(JSON.stringify(data));
  const ciphertext = Buffer.concat([cipher.update(json), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
};

const decryptJSON = (key, encrypted) => {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(encrypted.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
    decipher.final()
  ]);
  return JSON.parse(decrypted.toString());
};

module.exports = { deriveKey, encryptJSON, decryptJSON };