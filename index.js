const express = require('express');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
require('dotenv').config(); // Nạp biến môi trường từ file .env

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY; // Lấy key bí mật từ biến môi trường

// Kiểm tra xem biến môi trường có được thiết lập không
if (!secretKey) {
  throw new Error("SECRET_KEY is not defined. Make sure it's set in the environment variables.");
}

// Khởi tạo Firebase Admin SDK
const serviceAccount = require('./firebase-service-account.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const keysCollection = db.collection('keys');

// Endpoint để tạo key JWT
app.get('/generate-key', async (req, res) => {
  const { year, month, day, hour, minute } = req.query;

  // Lấy thời gian hiện tại
  const now = new Date();

  // Tạo thời gian hết hạn với giá trị mặc định nếu không được cung cấp
  const expiration = new Date(
    year ? parseInt(year) : now.getFullYear(),
    month ? parseInt(month) - 1 : now.getMonth(),
    day ? parseInt(day) : now.getDate(),
    hour ? parseInt(hour) : now.getHours(),
    minute ? parseInt(minute) : now.getMinutes()
  );

  try {
    // Tạo token JWT
    const token = jwt.sign({ exp: Math.floor(expiration.getTime() / 1000) }, secretKey);

    // Định dạng lại thời gian hết hạn
    const formattedExpiration = expiration.toLocaleString();

    // Lưu key và thời gian hết hạn vào Firestore
    const keyData = { token, expiresAt: formattedExpiration };
    await keysCollection.add(keyData);

    res.json(keyData);
  } catch (error) {
    console.error('Error generating key:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Endpoint để kiểm tra tính hợp lệ của key JWT
app.get('/validate-key', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ valid: false, message: 'Token is required' });
  }

  try {
    // Xác minh token
    jwt.verify(token, secretKey);
    res.json({ valid: true, message: 'Token is valid' });
  } catch (error) {
    res.json({ valid: false, message: 'Token is invalid or expired' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
