const express = require("express");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const axios = require("axios"); // Import thư viện axios để gọi API
require("dotenv").config(); // Nạp biến môi trường từ file .env
const path = require("path");
const { DateTime } = require("luxon"); // Import luxon
const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY; // Lấy key bí mật từ biến môi trường

// Kiểm tra xem biến môi trường có được thiết lập không
if (!secretKey) {
  throw new Error(
    "SECRET_KEY is not defined. Make sure it's set in the environment variables."
  );
}

// Khởi tạo Firebase Admin SDK bằng biến môi trường
admin.initializeApp({
  credential: admin.credential.cert({
    type: "service_account",
    project_id: process.env.PROJECT_ID,
    private_key_id: process.env.PRIVATE_KEY_ID,
    private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"), // Xử lý xuống dòng
    client_email: process.env.CLIENT_EMAIL,
    client_id: process.env.CLIENT_ID,
    auth_uri: process.env.AUTH_URI,
    token_uri: process.env.TOKEN_URI,
    auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.CLIENT_X509_CERT_URL,
  }),
});

const db = admin.firestore();
const keysCollection = db.collection("keys");

app.use(express.json());
// Phục vụ các file tĩnh trong thư mục 'public'
app.use(express.static("public"));

// Endpoint để phục vụ index.html tại đường dẫn gốc
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/check", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "quanly.html"));
});
// Endpoint để tạo token JWT
app.get("/generate-key", async (req, res) => {
  const { year, month, day, hour, minute } = req.query;

  // Lấy thời gian hiện tại theo múi giờ Asia/Ho_Chi_Minh
  const now = DateTime.now().setZone("Asia/Ho_Chi_Minh");

  // Tạo thời gian hết hạn dựa trên đầu vào hoặc thời gian hiện tại
  const expiration = DateTime.fromObject(
    {
      year: year ? parseInt(year) : now.year,
      month: month ? parseInt(month) : now.month,
      day: day ? parseInt(day) : now.day,
      hour: hour ? parseInt(hour) : now.hour,
      minute: minute ? parseInt(minute) : now.minute,
    },
    { zone: "Asia/Ho_Chi_Minh" }
  );

  try {
    // Tạo token JWT với thời gian hết hạn (tính bằng giây)
    const token = jwt.sign(
      { exp: Math.floor(expiration.toSeconds()) }, // Chuyển đổi thời gian hết hạn sang timestamp giây
      secretKey
    );

    // Định dạng lại thời gian hết hạn thành chuỗi dễ đọc
    const formattedExpiration = expiration.toFormat("yyyy-MM-dd HH:mm:ss");

    // Lưu token và thời gian hết hạn vào Firestore
    const keyData = {
      token,
      expiresAt: formattedExpiration,
      active: true,
    };
    await keysCollection.add(keyData);

    res.json(keyData);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal Server Error", error: error.message });
  }
});
// Endpoint để kiểm tra tính hợp lệ của token
app.get("/validate-key", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ valid: false, message: "Token is required" });
  }

  try {
    jwt.verify(token, secretKey); // Xác minh chữ ký của token

    // Kiểm tra trạng thái token trong Firestore
    const snapshot = await keysCollection.where("token", "==", token).get();
    if (snapshot.empty) {
      return res.json({
        valid: false,
        message: "Token not found in Firestore",
      });
    }

    const keyData = snapshot.docs[0].data();
    if (!keyData.active) {
      return res.json({
        valid: false,
        message: "Token is inactive or revoked",
      });
    }

    res.json({ valid: true, message: "Token is valid" });
  } catch (error) {
    res.json({ valid: false, message: "Token is invalid or expired" });
  }
});

app.post("/revoke-key", async (req, res) => {
  const { token } = req.body;

  try {
    const snapshot = await keysCollection.where("token", "==", token).get();
    if (snapshot.empty) {
      return res.status(404).json({ message: "Token not found" });
    }

    const docId = snapshot.docs[0].id;
    // Cập nhật cờ active thành false
    await keysCollection.doc(docId).update({ active: false });

    res.json({ message: "Token has been revoked" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/activate-key", async (req, res) => {
  const { token } = req.body;

  try {
    // Tìm token trong Firestore
    const snapshot = await keysCollection.where("token", "==", token).get();
    if (snapshot.empty) {
      return res.status(404).json({ message: "Token not found" });
    }

    const docId = snapshot.docs[0].id;
    // Cập nhật cờ active thành true
    await keysCollection.doc(docId).update({ active: true });

    res.json({ message: "Token has been activated" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
