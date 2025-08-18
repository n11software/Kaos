const mysql = require('mysql2/promise');
require('dotenv').config();

let db;

async function initDB() {
  db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });
  await db.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME}\``);
  await db.query(`USE \`${process.env.DB_NAME}\``);
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      uuid VARCHAR(36) UNIQUE PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      encrypted_blob JSON NOT NULL,
      plaintext_blob JSON NOT NULL,
      encrypted_keys JSON NOT NULL
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS chats (
      uuid VARCHAR(36) UNIQUE PRIMARY KEY,
      users JSON NOT NULL,
      data JSON NOT NULL
    )
  `);
  return db;
}

async function findUser(username) {
  const [rows] = await db.query(`SELECT * FROM users WHERE username = ?`, [username]);
  return rows[0] || null;
}

async function findUserById(id) {
  const [rows] = await db.query(`SELECT * FROM users WHERE uuid = ?`, [id]);
  return rows[0] || null;
}

async function createUser(username, password_hash, salt, encrypted_blob, plaintext_blob, encrypted_keys) {
  let uuid = require('crypto').randomUUID();
  await db.query(
    `INSERT INTO users (uuid, username, password_hash, salt, encrypted_blob, plaintext_blob, encrypted_keys) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [uuid, username, password_hash, salt, JSON.stringify(encrypted_blob), JSON.stringify(plaintext_blob), JSON.stringify(encrypted_keys)]
  );
}

function getDB() {
  return db;
}

module.exports = { initDB, findUser, findUserById, createUser, getDB };