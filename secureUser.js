const jwt = require('jsonwebtoken');
const { deriveKey, decryptJSON, encryptJSON } = require('./crypto-utils');
const { getDB } = require('./db');
require('dotenv').config();

async function getData(token) {
  let payload
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return { error: 'Invalid token' };
  }
  const db = getDB();
  const [rows] = await db.query(`SELECT * FROM users WHERE uuid = ?`, [payload.userId]);
  const user = rows[0];
  if (!user) return { error: 'User not found' };

  const key = Buffer.from(payload.key, 'base64');
  const encryptedBlob = typeof user.encrypted_blob === 'string' ? JSON.parse(user.encrypted_blob) : user.encrypted_blob;
  const decrypted = decryptJSON(key, encryptedBlob);
  const plaintext = typeof user.plaintext_blob === 'string' ? JSON.parse(user.plaintext_blob) : user.plaintext_blob;
  const encrypted_keys = typeof user.encrypted_keys === 'string' ? JSON.parse(user.encrypted_keys) : user.encrypted_keys;

  return {
    all: { ...plaintext, ...decrypted },
    username: user.username,
    encrypted: decrypted,
    plaintext,
    encrypted_keys,
    _meta: { id: user.id, key }
  };
}

async function saveData(token, newData) {
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  const db = getDB();
  const [rows] = await db.query(`SELECT * FROM users WHERE uuid = ?`, [payload.userId]);
  const user = rows[0];
  if (!user) throw new Error('User not found');

  const key = Buffer.from(payload.key, 'base64');
  const encrypted_keys = typeof user.encrypted_keys === 'string' ? JSON.parse(user.encrypted_keys) : user.encrypted_keys;

  const encrypted = {};
  const plaintext = {};

  console.log(encrypted_keys)

  for (const [keyName, value] of Object.entries(newData)) {
    if (encrypted_keys.includes(keyName)) {
      encrypted[keyName] = value;
    } else {
      plaintext[keyName] = value;
    }
  }

  const encrypted_blob = encryptJSON(key, encrypted);
  const plaintext_blob = JSON.stringify(plaintext);

  await db.query(
    `UPDATE users SET encrypted_blob = ?, plaintext_blob = ? WHERE uuid = ?`,
    [JSON.stringify(encrypted_blob), plaintext_blob, user.uuid]
  );
}

async function updateEncryptedKeys(token, newEncryptedKeys) {
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  const db = getDB();
  await db.query(
    `UPDATE users SET encrypted_keys = ? WHERE uuid = ?`,
    [JSON.stringify(newEncryptedKeys), payload.userId]
  );
  // Update the user's encrypted keys in the database
  const [rows] = await db.query(`SELECT * FROM users WHERE uuid = ?`,
    [payload.userId]);
  const user = rows[0];
  if (!user) throw new Error('User not found');
  user.encrypted_keys = typeof user.encrypted_keys === 'string' ? JSON.parse(user.encrypted_keys) : user.encrypted_keys;
  user.encrypted_keys = newEncryptedKeys;
  await db.query(`UPDATE users SET encrypted_keys = ? WHERE uuid = ?`,
    [JSON.stringify(user.encrypted_keys), user.uuid]);
  return user.encrypted_keys;
}

async function getEncryptedKeys(token) {
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  const db = getDB();
  const [rows] = await db.query(`SELECT encrypted_keys FROM users WHERE uuid = ?`, [payload.userId]);
  const user = rows[0];
  if (!user) throw new Error('User not found');
  return typeof user.encrypted_keys === 'string' ? JSON.parse(user.encrypted_keys) : user.encrypted_keys;
}

async function findUserById(id) {
  const db = getDB();
  const [rows] = await db.query(`SELECT * FROM users WHERE uuid = ?`, [id]);
  return rows[0] || null;
}

async function findUser(username) {
  const db = getDB();
  const [rows] = await db.query(`SELECT * FROM users WHERE username = ?`, [username]);
  return rows[0] || null;
}

module.exports = { getData, saveData, updateEncryptedKeys, getEncryptedKeys, findUserById, findUser };