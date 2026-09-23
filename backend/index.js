const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { prisma } = require("./database/db");

const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("API is running");
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashed },
    });
    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Could not create user" });
  }
});

app.listen(4000, () => console.log("Server running on port 4000"));