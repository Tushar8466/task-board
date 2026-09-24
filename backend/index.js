const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { prisma } = require("./database/db");
const authMiddleware = require("./middleware/auth");

const app = express();
app.use(express.json());
app.use(cors());

// Health check
app.get("/", (req, res) => {
  res.send("API is running");
});

// Register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email, and password are required" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { name, email, password: hashed },
    });

    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    if (err.code === "P2002") {
      return res.status(400).json({ error: "Email already registered" });
    }
    res.status(400).json({ error: "Could not create user" });
  }
});

app.get("/me", authMiddleware, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.userId },
    select: { id: true, name: true, email: true },
  });
  res.json(user);
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || "dev-secret-change-this",
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Create a workspace
app.post("/workspaces", authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Name is required" });

    const workspace = await prisma.workspace.create({
      data: {
        name,
        ownerId: req.userId,
        members: {
          create: { userId: req.userId, role: "owner" },
        },
      },
    });

    res.json(workspace);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create workspace" });
  }
});

// List workspaces the user belongs to
app.get("/workspaces", authMiddleware, async (req, res) => {
  try {
    const memberships = await prisma.workspaceMember.findMany({
      where: { userId: req.userId },
      include: { workspace: true },
    });

    const workspaces = memberships.map((m) => m.workspace);
    res.json(workspaces);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch workspaces" });
  }
});

app.listen(4000, () => console.log("Server running on port 4000"));