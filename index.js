const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { initDB, findUser, createUser, findUserById } = require('./db');
const { deriveKey, encryptJSON } = require('./crypto-utils');
const secureUser = require('./secureUser');
require('dotenv').config();
const fs = require('fs');

const app = express();
const PORT = 3002;


const cors = require('cors');
const { fstat } = require('fs');

const multer = require('multer');
const sharp = require('sharp');
const { getData, saveData } = require('./secureUser');
const { getDB } = require('./db');

const upload = multer({ limits: { fileSize: 1024 * 1024 * 1024 } }); // 5MB max

app.use(cors({
  origin: 'http://localhost:3001', // Your frontend
  credentials: true                // ✅ This enables cookies!
}));

app.use(express.json({ limit: '1gb' }));  // or whatever size you need

app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// for every page use this logic before sending the response
app.use(async (req, res, next) => {
  if (req.path.includes('/auth')) {
    next(); // Skip authentication for the auth page
    return;
  }
  const token = req.cookies.key ? req.cookies.key : req.cookies.token;
  if (!token) {
    res.redirect("https://n11.dev/auth?referrer=localhost:3001&href=/auth");
    return;
  }
  try {
    const data = await secureUser.getData(token);
    if (data.error) {
      console.log(data.error);
      res.redirect("https://n11.dev/auth?referrer=localhost:3001&href=/auth");
      return;
    }
    let user = await findUser(data.username);
    if (!user) {
      console.log("User not found");
      res.redirect("https://n11.dev/auth?referrer=localhost:3001&href=/auth");
      return;
    }
    // set data in req.user
    req.user = data
    next()
  } catch (err) {
    console.log(err)
    res.status(500).json({ error: 'Internal server error' });
  }
})

app.get('/cache/:name', async (req, res) => {
  const { name } = req.params;
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(path.join(__dirname, 'cache', name));
});

app.get('/', async (req, res) => {
  let key = req.user.all.kaosKey
  let uuid = await findUser(req.user.username);
  uuid = await uuid.uuid
  console.log(uuid)
  let chats = await getChats(uuid)
  let html = ``
  {
    // Get each chat
    for (let chat of chats) {
      // Get the display name and profile picture of each user in the chat excluding the current user
      let userDetails = [];
      for (let userUUID of chat.users) {
        if (userUUID === uuid) continue; // Skip current user
        let user = await findUserById(userUUID);
        console.log(user)
        if (user) {
          userDetails.push({
            username: user.plaintext_blob.displayName,
            profilePicture: user.plaintext_blob.pfp.pfp? ('data:image/png;base64,' + user.plaintext_blob.pfp.pfp) : '/cache/Default.jpg'
          });
        }
      }
      // Create HTML for the chat
      html += `
      <div class="chat" data-uuid="${chat.uuid}" onclick="window.location.href='/dm/${chat.uuid}'">
        <img src="${userDetails[0].profilePicture}" alt="${userDetails[0].username}" class="profile-picture">
        <div class="chat-info">
          <h3>${userDetails[0].username}</h3>
        </div>
      </div>
      `
    }
  }
  let file = fs.readFileSync(path.join(__dirname, 'pages', 'index.html'), 'utf8');
  file = file.replaceAll('{chats}', html);
  res.setHeader('Content-Type', 'text/html');
  res.send(file);
});

app.get('/dm/:id', async (req, res) => {
  if (req.params.id === 'new') {
    res.sendFile(path.join(__dirname, 'pages', 'newDM.html'));
    return
  }
  let key = aes.toPkcs8Pem(req.user.all.kaosKey)
  key = key.replaceAll('\n', '\\n');
  key = key.replaceAll('\r', '\\r');
  let content = fs.readFileSync(path.join(__dirname, 'pages', 'dm.html'), 'utf8');
  content = content.replace('{key}', key);
  let uuid = await findUser(req.user.username);
  uuid = await uuid.uuid
  content = content.replace('{uuid}', uuid);
  res.send(content);
});

app.post('/api/dm/get/:id', async (req, res) => {
  const { id } = req.params;
  let key = req.user.all.kaosKey
  let uuid = await findUser(req.user.username);
  uuid = await uuid.uuid
  let msgs = await getMessages(id, uuid, key);
  if (msgs.error) {
    res.status(404).json({ error: msgs.error });
    return;
  }
  res.json(msgs);
});

app.get('/auth', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'auth.html'));
});

app.get('/api/user/pfp/:uuid', async (req, res) => {
  let uuid = req.params.uuid;
  let user = await findUserById(uuid);
  res.setHeader('Content-Type', 'image/png');
  // cache for a minute
  res.setHeader("Cache-Control", "public, max-age=3600");
  if (user.plaintext_blob.pfp.pfp) {
    res.send(Buffer.from(user.plaintext_blob.pfp.pfp, 'base64'));
  } else {
    res.sendFile(path.join(__dirname, 'cache', 'Default.jpg'));
  }
})

app.get('/api/user/displayName/:uuid', async (req, res) => {
  let uuid = req.params.uuid;
  let user = await findUserById(uuid);
  let displayName = user.plaintext_blob.displayName || user.username;
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.json({ displayName });
})

app.get('/api/user/uuid/:username', async (req, res) => {
  let username = req.params.username
  let user = await findUser(username);
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.json({ uuid: user.uuid });
})

const aes = require('./aes.js')

app.post('/api/registerKey', async (req, res) => {
  // in theory we should already be logged in
  // if req.user.encrypted.kaosKey and req.user.plaintext.kaosCert are not present
  if (true) {
    // generate new AES256 cert and key
    const { privateKeyPem, certPem } = aes.createIdentity(req.user.username);

    // Store these in the user's encrypted data
    const token = req.cookies.key ? req.cookies.key : req.cookies.token;
    const data = await secureUser.getData(token);
    if (data.error) return res.status(401).json({ error: data.error });
    
    const newEncrypted = {
      ...data.encrypted,
      kaosKey: privateKeyPem, // Store the private key securely
    };

    // TODO: add to encrypted_keys if not already present
    
    const newPlaintext = {
      ...data.plaintext,
      kaosCert: certPem, // Store the public cert
    };

    let encrypted_keys = await req.user.encrypted_keys
    encrypted_keys.push('kaosKey');
    // save
    await secureUser.updateEncryptedKeys(token, encrypted_keys);
    

    // Merge and save
    await saveData(token, { ...newPlaintext, ...newEncrypted });
    res.json({
      success: true
    })
    return;
  } else {
    res.json({
      success: false
    })
  }
})

let SocketDM = {}

// create websocket using the same HTTP server as Express
const WebSocket = require('ws');
const http = require('http');
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const pathname = require('url').parse(request.url).pathname;
  if (pathname.startsWith('/ws/dm/')) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws, req) => {
  let chatId = req.url.split('/ws/dm/')[1];
  if (!SocketDM[chatId]) {
    SocketDM[chatId] = new Set();
  }
  SocketDM[chatId].add(ws);
  ws.on('close', () => {
    SocketDM[chatId].delete(ws);
  });
});

wss.addListener('error', (err) => {
  console.error('WebSocket error:', err);
});

wss.addListener('listening', () => {
  console.log('WebSocket server is listening');
});

app.post('/api/sendMessage', async (req, res) => {
  let key = req.user.all.kaosKey
  let userUUID = await findUser(req.user.username);
  userUUID = await userUUID.uuid
  let { toWhom, msg, uuid } = req.body;
  if (uuid) {
    // get users in chat
    let chat = await getDB().query(
      `SELECT * FROM chats WHERE uuid = ?`, [uuid]
    );
    if (chat[0].length === 0) {
      return res.status(404).json({ error: 'Chat not found' });
    }
    let users = chat[0][0].users;
    toWhom = users;
  } else {
    // check if toWhom is already in the db
    let chat = await getDB().query(
      `SELECT * FROM chats WHERE JSON_CONTAINS(users, JSON_QUOTE(?))`,
      [userUUID]
    );
    if (chat[0].length > 0) {
      uuid = chat[0][0].uuid;
    } else {
      uuid = 0;
    }
  }
  if (toWhom.length === 0) {
    return res.status(400).json({ error: 'No recipients specified' });
  }
  try {
    console.log(userUUID)
    let result = await sendMessage(userUUID, toWhom, msg, uuid);
    if (result.error) {
      return res.status(400).json({ error: result.error });
    }
    res.json(result);
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Internal server error' });
  }

  // fetch('/api/sendMessage', {
  //   method: 'POST',
  //   headers: {
  //     'Content-Type': 'application/json'
  //   },
  //   body: JSON.stringify({ toWhom, msg, uuid })
  // });
});

let sendMessage = async (from, toWhom, msg, uuid='0') => {
  // Get each user in toWhom
  let unix = Date.now();
  let users = {}
  let fromUser = await findUserById(from);
  if (!fromUser) return {error: 'Sender not found'};
  // encrypt using each users cert in their ...
  if (!fromUser.plaintext_blob.kaosCert) {
    return {error: 'Sender has not signed up for Kaos'};
  }
  let encMsg = aes.encryptFor(fromUser.plaintext_blob.kaosCert, msg);
  users[fromUser.uuid] = {msg: encMsg, date: unix, sender: fromUser.uuid, read: {}}
  for (let username of toWhom) {
    let user = await findUserById(username);
    if (!user) return {error: `User not found: ${username}`};
    if (user.plaintext_blob.kaosCert === undefined) {
      return {error: `User ${username} has not signed up for Kaos`};
    }
    let encMsg = aes.encryptFor(user.plaintext_blob.kaosCert, msg);
    users[user.uuid] = {msg: encMsg, date: unix, sender: fromUser.uuid, read: {}}
  }
  // If UUID = 0 make a new chat if not get current chat
  if (uuid === 0) {
    getDB().query(
      `INSERT INTO chats (uuid, users, data) VALUES (?, ?, ?)`,
      [crypto.randomUUID(), JSON.stringify(Object.keys(users)), '['+JSON.stringify(users)+']']
    );
  } else {
    let chat = await getDB().query(
      `SELECT * FROM chats WHERE uuid = ?`, [uuid]
    );
    // jsonify
    let obj = chat[0][0].data
    obj.push(users)
    chat[0][0].data = JSON.stringify(obj)
    // update
    await getDB().query(
      `UPDATE chats SET data = ? WHERE uuid = ?`,
      [chat[0][0].data, uuid]
    );
  }

  // send to ws
  for (let ws of (SocketDM[uuid] || [])) {
    ws.send(JSON.stringify({ type: 'message', data: users }));
  }
  return {success: true, data: users[fromUser.uuid]}
}

const getMessages = async (chatUuid, userUUID, key) => {
  const path = `$."${userUUID}"`; // dynamic JSON path to that user's object

  const [rows] = await getDB().query(
    `
    SELECT
      jt.idx,
      CAST(JSON_UNQUOTE(JSON_EXTRACT(uobj, '$.date')) AS UNSIGNED) AS date_ms,
      JSON_EXTRACT(uobj, '$.msg')    AS msg_json,
      JSON_UNQUOTE(JSON_EXTRACT(uobj, '$.sender')) AS sender,
      JSON_EXTRACT(uobj, '$.read')   AS \`read\`
    FROM chats c
    JOIN JSON_TABLE(c.data, '$[*]'
      COLUMNS (
        idx FOR ORDINALITY,
        obj JSON PATH '$'
      )
    ) AS jt
    /* pick this user's inner object out of each element */
    CROSS JOIN LATERAL (
      SELECT JSON_EXTRACT(jt.obj, ?) AS uobj
    ) pick
    WHERE c.uuid = ?
      AND uobj IS NOT NULL
    ORDER BY date_ms DESC, jt.idx DESC   -- <— stable tiebreaker
    LIMIT 100
    `,
    [path, chatUuid]
  );

  // decrypt
  return rows.map(r => {
    let msg;
    try {
      const m = r.msg_json;
      msg = (m && m.alg === 'RSA-OAEP-256+AES-256-GCM')
        ? aes.decryptFrom(key, m)
        : 'Unsupported or bad msg';
    } catch {
      msg = 'Bad msg json';
    }
    return { date: r.date_ms, sender: r.sender, read: !!r.read, msg };
  }).reverse()
};



let getChats = async (userUUID) => {
  let chats = await getDB().query(
    `SELECT * FROM chats where JSON_CONTAINS(users, JSON_QUOTE(?))`, [userUUID]
  );
  // get rid of chats[0][i][data]
  chats[0] = chats[0].map(chat => {
    delete chat.data;
    return chat;
  });
  return chats[0];
}


// 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'pages', '404.html'));
});

(async () => {
  await initDB();
  server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
})();