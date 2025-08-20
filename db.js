const mysql = require('mysql2/promise');
require('dotenv').config();

let pool;

async function initDB() {
  // Create connection to ensure database exists first
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });

  await connection.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME}\``);
  await connection.end();

  // Now use pool with selected DB
  pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  const conn = await pool.getConnection();
  await conn.query(`
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
  await conn.query(`
    CREATE TABLE IF NOT EXISTS sso (
      uuid VARCHAR(36) UNIQUE PRIMARY KEY,
      domain TEXT NOT NULL,
      location TEXT NOT NULL,
      trusted BOOLEAN NOT NULL
    )
  `);
  await conn.query(`
    CREATE TABLE IF NOT EXISTS chats (
      uuid VARCHAR(36) UNIQUE PRIMARY KEY,
      users JSON NOT NULL,
      data JSON NOT NULL
    )
  `);
  conn.release();
}

async function findUser(username) {
  const [rows] = await pool.query(`SELECT * FROM users WHERE username = ?`, [username]);
  return rows[0] || null;
}

async function findUserById(id) {
  const [rows] = await pool.query(`SELECT * FROM users WHERE uuid = ?`, [id]);
  return rows[0] || null;
}

async function findSSO(domain) {
  const [rows] = await pool.query(`SELECT * FROM sso WHERE domain = ?`, [domain]);
  return rows[0] || null;
}

async function createUser(username, password_hash, salt, encrypted_blob, plaintext_blob, encrypted_keys) {
  const uuid = require('crypto').randomUUID();
  await pool.query(
    `INSERT INTO users (uuid, username, password_hash, salt, encrypted_blob, plaintext_blob, encrypted_keys) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [uuid, username, password_hash, salt, JSON.stringify(encrypted_blob), JSON.stringify(plaintext_blob), JSON.stringify(encrypted_keys)]
  );
}

function getDB() {
  return pool;
}

module.exports = { initDB, findUser, findUserById, createUser, getDB, findSSO };
