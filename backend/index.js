import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import pkg from "pg";

dotenv.config();

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get("/", (req, res) => {
  res.send("API Running ✅");
});

app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("select now()");
    res.json({ db: "connected", time: result.rows[0] });
  } catch (err) {
    res.status(500).json({ db: "failed", error: err.message });
  }
});

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      "insert into users(username,email,password) values($1,$2,$3)",
      [username, email, hash]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("select * from users where email=$1", [email]);
  if (!result.rows.length) return res.status(401).json({ error: "Invalid email" });

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ token, username: user.username });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));
