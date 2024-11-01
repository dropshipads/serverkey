const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config(); // Import và cấu hình dotenv

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY; // Lấy key bí mật từ biến môi trường

// Middleware để phục vụ các file tĩnh trong thư mục public
app.use(express.static(path.join(__dirname, 'public')));

// Endpoint để tạo key JWT
app.get('/generate-key', (req, res) => {
  const { year, month, day, hour, minute } = req.query;

  // Lấy thời gian hiện tại
  const now = new Date();

  // Tạo thời gian hết hạn
  const expiration = new Date(
    year || now.getFullYear(),
    month ? month - 1 : now.getMonth(),
    day || now.getDate(),
    hour || now.getHours(),
    minute || now.getMinutes()
  );

  // Tính thời gian hết hạn theo giây
  const expiresIn = Math.floor(expiration.getTime() / 1000) - Math.floor(now.getTime() / 1000);

  // Tạo token JWT
  const token = jwt.sign({ exp: Math.floor(expiration.getTime() / 1000) }, secretKey);

  // Lưu key và thời gian hết hạn vào file JSON
  const keyData = { token, expiresAt: expiration };
  const keysFilePath = path.join(__dirname, 'keys.json');

  // Đọc dữ liệu hiện có từ file JSON
  let keys = [];
  if (fs.existsSync(keysFilePath)) {
    keys = JSON.parse(fs.readFileSync(keysFilePath, 'utf8'));
  }

  // Thêm key mới vào danh sách
  keys.push(keyData);

  // Ghi dữ liệu mới vào file JSON
  fs.writeFileSync(keysFilePath, JSON.stringify(keys, null, 2));

  res.json(keyData);
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
