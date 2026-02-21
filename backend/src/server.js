const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const XLSX = require("xlsx");
const fs = require("fs");
const path = require("path");
const { signToken, authRequired, roleRequired, anyRoleRequired } = require("./auth");
const User = require("./models/User");
const Student = require("./models/Student");
const CollegePayment = require("./models/CollegePayment");
const HostelFeeMaster = require("./models/HostelFeeMaster");
const HostelAttendance = require("./models/HostelAttendance");
const HostelPayment = require("./models/HostelPayment");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

const truthy = (value) => ["1", "true", "yes", "y", "on"].includes(String(value || "").toLowerCase());

let mongoMemoryServer = null;
const resolveMongoUri = async () => {
  if (process.env.MONGODB_URI) return process.env.MONGODB_URI;
  if (process.env.NODE_ENV === "production" || !truthy(process.env.USE_IN_MEMORY_DB)) {
    throw new Error(
      "MONGODB_URI is missing in environment variables (set USE_IN_MEMORY_DB=true for local dev)"
    );
  }

  const { MongoMemoryServer } = require("mongodb-memory-server");
  const defaultDbPath = path.join(process.cwd(), ".data", "mongo");
  const dbPath = String(process.env.IN_MEMORY_DB_PATH || defaultDbPath).trim();
  fs.mkdirSync(dbPath, { recursive: true });

  mongoMemoryServer = await MongoMemoryServer.create({
    instance: {
      dbPath
    }
  });
  return mongoMemoryServer.getUri("website_db");
};

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS not allowed"));
      }
    },
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(express.json());

const toNumber = (value) => Number(value || 0);

const sanitizeUser = (user) => ({
  id: String(user._id),
  email: user.email,
  name: user.name,
  role: user.role,
  active: user.active
});

const computeStudentBalances = async (pin) => {
  const [student, collegePayments, hostelAttendance, hostelPayments] = await Promise.all([
    Student.findOne({ pin }),
    CollegePayment.find({ pin }),
    HostelAttendance.find({ pin }),
    HostelPayment.find({ pin })
  ]);

  if (!student) return null;

  const collegePaid = collegePayments.reduce((sum, item) => sum + toNumber(item.amountPaid), 0);
  const collegeBalance = Math.max(0, toNumber(student.collegeTotalFee) - collegePaid);

  const hostelCharged = hostelAttendance.reduce(
    (sum, item) => sum + toNumber(item.calculatedFee),
    0
  );
  const hostelPaid = hostelPayments.reduce((sum, item) => sum + toNumber(item.amountPaid), 0);
  const hostelBalance = Math.round(Math.max(0, hostelCharged - hostelPaid));

  return {
    pin: student.pin,
    name: student.name,
    course: student.course,
    collegeTotalFee: student.collegeTotalFee,
    collegePaid,
    collegeBalance,
    hostelCharged,
    hostelPaid,
    hostelBalance
  };
};

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    dbConnected: mongoose.connection.readyState === 1
  });
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user || !user.active) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken(user);
    res.json({ token, user: sanitizeUser(user) });
  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.auth.sub);
    if (!user || !user.active) return res.status(401).json({ message: "Unauthorized" });
    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    res.status(500).json({ message: "Failed to load user" });
  }
});

// Billing routes: only logged-in staff/admin can create/update data.
app.post("/api/students", authRequired, anyRoleRequired(["admin", "staff"]), async (req, res) => {
  try {
    const { pin, name, course, collegeTotalFee } = req.body;
    if (!pin || !name || !course || collegeTotalFee === undefined) {
      return res.status(400).json({ message: "pin, name, course, collegeTotalFee are required" });
    }

    const student = await Student.findOneAndUpdate(
      { pin },
      { pin, name, course, collegeTotalFee: toNumber(collegeTotalFee) },
      { upsert: true, new: true, runValidators: true }
    );
    res.status(201).json(student);
  } catch (error) {
    res.status(500).json({ message: "Failed to save student" });
  }
});

app.get("/api/students", authRequired, anyRoleRequired(["admin", "staff"]), async (req, res) => {
  try {
    const students = await Student.find().sort({ createdAt: -1 });
    res.json(students);
  } catch (error) {
    res.status(500).json({ message: "Failed to load students" });
  }
});

app.post(
  "/api/college-payments",
  authRequired,
  anyRoleRequired(["admin", "staff"]),
  async (req, res) => {
  try {
    const { date, pin, amountPaid } = req.body;
    if (!date || !pin || !amountPaid) {
      return res.status(400).json({ message: "date, pin, amountPaid are required" });
    }

    const student = await Student.findOne({ pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const payment = await CollegePayment.create({
      date: new Date(date),
      pin,
      amountPaid: toNumber(amountPaid)
    });
    res.status(201).json(payment);
  } catch (error) {
    res.status(500).json({ message: "Failed to save college payment" });
  }
  }
);

app.post("/api/hostel-fees", authRequired, anyRoleRequired(["admin", "staff"]), async (req, res) => {
  try {
    const { month, monthlyFee } = req.body;
    if (!month || monthlyFee === undefined) {
      return res.status(400).json({ message: "month and monthlyFee are required" });
    }

    const fee = await HostelFeeMaster.findOneAndUpdate(
      { month },
      { month, monthlyFee: toNumber(monthlyFee) },
      { upsert: true, new: true, runValidators: true }
    );
    res.status(201).json(fee);
  } catch (error) {
    res.status(500).json({ message: "Failed to save hostel fee" });
  }
});

app.get("/api/hostel-fees", authRequired, anyRoleRequired(["admin", "staff"]), async (req, res) => {
  try {
    const data = await HostelFeeMaster.find().sort({ month: 1 });
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: "Failed to load hostel fees" });
  }
});

app.post(
  "/api/hostel-attendance",
  authRequired,
  anyRoleRequired(["admin", "staff"]),
  async (req, res) => {
  try {
    const { pin, month, totalDays, daysStayed } = req.body;
    if (!pin || !month || !totalDays) {
      return res.status(400).json({ message: "pin, month, totalDays are required" });
    }

    const student = await Student.findOne({ pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const monthly = await HostelFeeMaster.findOne({ month });
    if (!monthly) return res.status(404).json({ message: "Month not configured in hostel fee master" });

    const total = Math.max(1, toNumber(totalDays));
    const stayed = Math.max(0, Math.min(toNumber(daysStayed), total));
    const calculatedFee = Math.round((toNumber(monthly.monthlyFee) / total) * stayed);

    const attendance = await HostelAttendance.create({
      pin,
      month,
      totalDays: total,
      daysStayed: stayed,
      calculatedFee
    });

    res.status(201).json(attendance);
  } catch (error) {
    res.status(500).json({ message: "Failed to save hostel attendance" });
  }
  }
);

app.post(
  "/api/hostel-payments",
  authRequired,
  anyRoleRequired(["admin", "staff"]),
  async (req, res) => {
  try {
    const { date, pin, month, amountPaid } = req.body;
    if (!date || !pin || !month || !amountPaid) {
      return res.status(400).json({ message: "date, pin, month, amountPaid are required" });
    }

    const student = await Student.findOne({ pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const payment = await HostelPayment.create({
      date: new Date(date),
      pin,
      month,
      amountPaid: toNumber(amountPaid)
    });
    res.status(201).json(payment);
  } catch (error) {
    res.status(500).json({ message: "Failed to save hostel payment" });
  }
  }
);

app.get(
  "/api/dashboard/students",
  authRequired,
  anyRoleRequired(["admin", "staff"]),
  async (req, res) => {
  try {
    const students = await Student.find().sort({ createdAt: -1 });
    const balances = await Promise.all(students.map((item) => computeStudentBalances(item.pin)));
    res.json(balances.filter(Boolean));
  } catch (error) {
    res.status(500).json({ message: "Failed to load dashboard" });
  }
  }
);

app.get("/api/receipt/:pin", authRequired, anyRoleRequired(["admin", "staff"]), async (req, res) => {
  try {
    const data = await computeStudentBalances(req.params.pin);
    if (!data) return res.status(404).json({ message: "Student not found" });

    res.json({
      generatedOn: new Date().toISOString(),
      ...data
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to build receipt" });
  }
});

// Admin user management
app.get("/api/admin/users", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json(users.map(sanitizeUser));
  } catch (error) {
    res.status(500).json({ message: "Failed to load users" });
  }
});

app.post("/api/admin/users", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const { email, name, role, password, active } = req.body || {};
    if (!email || !name || !role || !password) {
      return res.status(400).json({ message: "email, name, role, password are required" });
    }
    if (!["admin", "staff"].includes(role)) {
      return res.status(400).json({ message: "role must be admin or staff" });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.findOneAndUpdate(
      { email: String(email).toLowerCase().trim() },
      { email: String(email).toLowerCase().trim(), name: String(name).trim(), role, passwordHash, active: active !== false },
      { upsert: true, new: true, runValidators: true }
    );
    res.status(201).json(sanitizeUser(user));
  } catch (error) {
    res.status(500).json({ message: "Failed to save user" });
  }
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

const parseCsvLine = (line) => {
  // Minimal CSV parser supporting quoted fields with commas.
  const out = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i + 1] === '"') {
      current += '"';
      i++;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === "," && !inQuotes) {
      out.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current.trim());
  return out;
};

const rowsFromUpload = (file) => {
  const name = (file.originalname || "").toLowerCase();
  const buf = file.buffer;

  if (name.endsWith(".xlsx") || name.endsWith(".xls")) {
    const wb = XLSX.read(buf, { type: "buffer" });
    const sheetName = wb.SheetNames[0];
    if (!sheetName) return [];
    const sheet = wb.Sheets[sheetName];
    // Returns array of objects with keys from first row.
    return XLSX.utils.sheet_to_json(sheet, { defval: "" });
  }

  // Default to CSV.
  const text = buf.toString("utf8");
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const headers = parseCsvLine(lines[0]).map((h) => h.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvLine(lines[i]);
    const row = {};
    for (let c = 0; c < headers.length; c++) {
      row[headers[c]] = cols[c] === undefined ? "" : cols[c];
    }
    rows.push(row);
  }
  return rows;
};

app.post(
  "/api/admin/users/import",
  authRequired,
  roleRequired("admin"),
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "file is required" });

      const rows = rowsFromUpload(req.file);
      if (!rows || rows.length === 0) return res.status(400).json({ message: "No rows found" });

      let created = 0;
      let updated = 0;
      const errors = [];

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i] || {};
        const rowEmail = String(row.email || row.Email || "").toLowerCase().trim();
        const rowName = String(row.name || row.Name || "").trim();
        const rowRole = String(row.role || row.Role || "").toLowerCase().trim();
        const rowPassword = String(row.password || row.Password || "").trim();
        const rowActiveRaw = String(row.active || row.Active || "").trim();

        if (!rowEmail || !rowName || !rowRole || !rowPassword) {
          errors.push({ row: i + 2, message: "Missing required fields (email,name,role,password)" });
          continue;
        }
        if (!["admin", "staff"].includes(rowRole)) {
          errors.push({ row: i + 2, message: "Invalid role (admin/staff)" });
          continue;
        }

        const passwordHash = await bcrypt.hash(String(rowPassword), 10);
        const active =
          rowActiveRaw === ""
            ? true
            : ["true", "1", "yes"].includes(String(rowActiveRaw).toLowerCase());

        const existing = await User.findOne({ email: rowEmail });
        const user = await User.findOneAndUpdate(
          { email: rowEmail },
          { email: rowEmail, name: rowName, role: rowRole, passwordHash, active },
          { upsert: true, new: true, runValidators: true }
        );

        if (existing) updated += 1;
        else created += 1;
      }

      res.json({ created, updated, errors });
    } catch (error) {
      res.status(500).json({ message: "Import failed" });
    }
  }
);

app.get("/api/admin/users/template", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="users_template.csv"');
    res.send(
      "email,name,role,password,active\n" +
        "staff1@example.com,Staff One,staff,ChangeMe123!,true\n" +
        "admin2@example.com,Second Admin,admin,ChangeMe123!,true\n"
    );
  } catch (error) {
    res.status(500).json({ message: "Failed to build template" });
  }
});

const start = async () => {
  try {
    const mongoUri = await resolveMongoUri();
    await mongoose.connect(mongoUri);

    // Seed initial admin if none exists.
    const adminCount = await User.countDocuments({ role: "admin" });
    if (adminCount === 0 && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const email = String(process.env.ADMIN_EMAIL).toLowerCase().trim();
      const name = String(process.env.ADMIN_NAME || "Admin").trim();
      const passwordHash = await bcrypt.hash(String(process.env.ADMIN_PASSWORD), 10);
      await User.create({ email, name, role: "admin", passwordHash, active: true });
      console.log(`Seeded admin user: ${email}`);
    }

    const server = app.listen(PORT, () => {
      console.log(`Backend listening on port ${PORT}`);

      if (truthy(process.env.SMOKE_TEST)) {
        const http = require("http");
        const url = `http://localhost:${PORT}/api/health`;
        const req = http.get(url, (resp) => {
          let data = "";
          resp.setEncoding("utf8");
          resp.on("data", (chunk) => {
            data += chunk;
          });
          resp.on("end", async () => {
            console.log(`SMOKE_TEST /api/health -> ${resp.statusCode} ${data}`);
            server.close(async () => {
              try {
                await mongoose.disconnect();
              } catch {}
              try {
                if (mongoMemoryServer) await mongoMemoryServer.stop();
              } catch {}
              process.exit(resp.statusCode === 200 ? 0 : 1);
            });
          });
        });

        req.on("error", (err) => {
          console.error("SMOKE_TEST failed:", err.message);
          process.exit(1);
        });
        req.setTimeout(10_000, () => {
          console.error("SMOKE_TEST timed out");
          process.exit(1);
        });
      }
    });

    const shutdown = async () => {
      try {
        await mongoose.disconnect();
      } catch {}
      try {
        if (mongoMemoryServer) await mongoMemoryServer.stop();
      } catch {}
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } catch (error) {
    console.error("Server startup failed:", error.message);
    process.exit(1);
  }
};

start();
