const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const XLSX = require("xlsx");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");
const { signToken, authRequired, roleRequired, anyRoleRequired } = require("./auth");
const User = require("./models/User");
const Student = require("./models/Student");
const CollegePayment = require("./models/CollegePayment");
const HostelFeeMaster = require("./models/HostelFeeMaster");
const HostelAttendance = require("./models/HostelAttendance");
const HostelPayment = require("./models/HostelPayment");
const StudentImport = require("./models/StudentImport");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

const USER_ROLES = ["admin", "principal", "accountant", "staff"];
const BILLING_ROLES = ["admin", "principal", "accountant", "staff"];

const normalizeRole = (roleRaw) => {
  const role = String(roleRaw || "").toLowerCase().trim();
  if (role === "prncipal" || role === "pricipal") return "principal";
  if (role === "accountent") return "accountant";
  return role;
};

const normalizeCollegeKey = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "default";
  if (raw.toLowerCase() === "default") return "default";
  if (/^\d+$/.test(raw)) return raw.padStart(3, "0");
  return raw;
};

const collegeMatch = (collegeKeyRaw) => {
  const collegeKey = normalizeCollegeKey(collegeKeyRaw);
  if (collegeKey === "default") {
    return { $or: [{ collegeKey: "default" }, { collegeKey: { $exists: false } }, { collegeKey: "" }] };
  }
  return { collegeKey };
};

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

const isLocalDevOrigin = (origin) => {
  const value = String(origin || "");
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(value);
};

// Apply CORS to API routes only.
// Important: browsers often send an Origin header even for same-origin module scripts/styles when served via tunnels.
// If we throw on unknown origins, the SPA may fail to load (blank page). Instead:
// - Always allow same-origin requests.
// - If origin isn't allowed, disable CORS without throwing (browser will block cross-origin use, but server stays up).
app.use(
  "/api",
  cors((req, callback) => {
    const origin = String(req.header("Origin") || "").trim();
    const host = String(req.header("Host") || "").trim();
    const proto = String(req.header("X-Forwarded-Proto") || req.protocol || "http").trim();

    const sameOrigin = origin && host && origin === `${proto}://${host}`;

    const allow =
      !origin ||
      sameOrigin ||
      allowedOrigins.length === 0 ||
      allowedOrigins.includes(origin) ||
      (process.env.NODE_ENV !== "production" && isLocalDevOrigin(origin));

    callback(null, { origin: allow, allowedHeaders: ["Content-Type", "Authorization"] });
  })
);
app.use(express.json());

const toNumber = (value) => Number(value || 0);

// If `frontend/dist` exists (built with `npm run build`), serve it from the backend.
// This enables simple one-URL deployments (useful for local + tunnel sharing).
(() => {
  try {
    const distDir = path.join(__dirname, "..", "..", "frontend", "dist");
    const indexFile = path.join(distDir, "index.html");
    if (!fs.existsSync(indexFile)) {
      app.get("/", (req, res) => {
        res.status(200).send("Backend is running. Try /api/health");
      });
      return;
    }

    // Prevent stale HTML caching (common cause of "blank page" when assets are re-hashed).
    app.use((req, res, next) => {
      if (req.method === "GET" && (req.path === "/" || req.path.endsWith(".html"))) {
        res.setHeader("Cache-Control", "no-store");
      }
      next();
    });

    app.use(express.static(distDir));
    // SPA fallback for non-API routes
    app.get(/^\/(?!api\/).*/, (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      res.sendFile(indexFile);
    });
  } catch {
    // Ignore static serving errors; API can still run.
  }
})();

const sanitizeUser = (user) => ({
  id: String(user._id),
  collegeKey: user.collegeKey || "default",
  email: user.email,
  name: user.name,
  role: user.role,
  mustChangePassword: Boolean(user.mustChangePassword),
  active: user.active
});

const pickFirst = (obj, keys) => {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
  }
  return undefined;
};

const normalizeStudentRow = (row) => {
  const pin = String(pickFirst(row, ["pin", "PIN", "Pin"]) || "").trim();
  const name = String(pickFirst(row, ["name", "Name"]) || "").trim();
  const course = String(pickFirst(row, ["course", "Course"]) || "").trim();
  const phone = String(
    pickFirst(row, ["phone", "Phone", "mobile", "Mobile", "whatsapp", "WhatsApp"]) || ""
  ).trim();
  const hasHostelRaw = pickFirst(row, [
    "hasHostel",
    "has_hostel",
    "Hostel",
    "hostel",
    "hostelEnabled",
    "hostel_enabled",
    "isHostel",
    "is_hostel"
  ]);
  const hasHostel = truthy(hasHostelRaw);

  const collegeTotalFeeRaw = pickFirst(row, [
    "collegeTotalFee",
    "college_total_fee",
    "College Total Fee",
    "CollegeTotalFee",
    "College Total",
    "Total Fee",
    "totalFee"
  ]);
  const hasCollegeTotalFee =
    collegeTotalFeeRaw !== undefined && String(collegeTotalFeeRaw).trim().length > 0;

  return {
    pin,
    name,
    course,
    phone,
    hasHostel,
    collegeTotalFee: hasCollegeTotalFee ? toNumber(collegeTotalFeeRaw) : null
  };
};

const importStudents = async (collegeKey, rows) => {
  const ops = rows.map((row) => ({
    updateOne: {
      filter: { collegeKey, pin: row.pin },
      update: {
        $set: {
          collegeKey,
          pin: row.pin,
          name: row.name,
          course: row.course,
          phone: row.phone || "",
          hasHostel: Boolean(row.hasHostel),
          collegeTotalFee: toNumber(row.collegeTotalFee)
        }
      },
      upsert: true
    }
  }));

  const result = await Student.bulkWrite(ops, { ordered: false });
  const created = result.upsertedCount ?? Object.keys(result.upsertedIds || {}).length ?? 0;
  const updated = result.modifiedCount ?? 0;
  return { created, updated, total: rows.length };
};

const computeStudentBalances = async (collegeKey, pin) => {
  const collegeFilter = collegeMatch(collegeKey);
  const [student, collegePayments, hostelAttendance, hostelPayments] = await Promise.all([
    Student.findOne({ ...collegeFilter, pin }),
    CollegePayment.find({ ...collegeFilter, pin }),
    HostelAttendance.find({ ...collegeFilter, pin }),
    HostelPayment.find({ ...collegeFilter, pin })
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
    collegeKey: student.collegeKey || normalizeCollegeKey(collegeKey),
    pin: student.pin,
    name: student.name,
    course: student.course,
    phone: student.phone || "",
    hasHostel: Boolean(student.hasHostel),
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
    res.json({ user: sanitizeUser(req.user) });
  } catch (error) {
    res.status(500).json({ message: "Failed to load user" });
  }
});

app.post("/api/auth/change-password", authRequired, async (req, res) => {
  try {
    const { newPassword } = req.body || {};
    const pw = String(newPassword || "");
    if (pw.length < 8) {
      return res.status(400).json({ message: "newPassword must be at least 8 characters" });
    }

    req.user.passwordHash = await bcrypt.hash(pw, 10);
    req.user.mustChangePassword = false;
    await req.user.save();

    const token = signToken(req.user);
    res.json({ token, user: sanitizeUser(req.user) });
  } catch (error) {
    res.status(500).json({ message: "Failed to change password" });
  }
});

// Billing routes: only logged-in staff/admin can create/update data.
app.post("/api/students", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const { pin, name, course, phone, collegeTotalFee, hasHostel } = req.body;
    if (!pin || !name || !course || collegeTotalFee === undefined) {
      return res.status(400).json({ message: "pin, name, course, collegeTotalFee are required" });
    }

    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.body?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const update = {
      collegeKey,
      pin,
      name,
      course,
      phone: String(phone || "").trim(),
      collegeTotalFee: toNumber(collegeTotalFee)
    };
    if (req.user.role === "admin") update.hasHostel = Boolean(hasHostel);

    const student = await Student.findOneAndUpdate({ collegeKey, pin }, update, {
      upsert: true,
      new: true,
      runValidators: true
    });
    res.status(201).json(student);
  } catch (error) {
    res.status(500).json({ message: "Failed to save student" });
  }
});

app.get("/api/students", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const filter =
      req.user.role === "admin"
        ? req.query.collegeKey
          ? collegeMatch(req.query.collegeKey)
          : {}
        : collegeMatch(req.user.collegeKey);

    const students = await Student.find(filter).sort({ createdAt: -1 });
    res.json(students);
  } catch (error) {
    res.status(500).json({ message: "Failed to load students" });
  }
});

app.post(
  "/api/college-payments",
  authRequired,
  anyRoleRequired(BILLING_ROLES),
  async (req, res) => {
  try {
    const { date, pin, amountPaid, phone } = req.body;
    if (!pin || !amountPaid) {
      return res.status(400).json({ message: "pin, amountPaid are required" });
    }

    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.body?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const student = await Student.findOne({ ...collegeMatch(collegeKey), pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const payment = await CollegePayment.create({
      date: date ? new Date(date) : new Date(),
      collegeKey,
      pin,
      amountPaid: toNumber(amountPaid),
      phone: String(phone || "").trim()
    });
    res.status(201).json(payment);
  } catch (error) {
    res.status(500).json({ message: "Failed to save college payment" });
  }
  }
);

app.post("/api/hostel-fees", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const { month, monthlyFee } = req.body;
    if (!month || monthlyFee === undefined) {
      return res.status(400).json({ message: "month and monthlyFee are required" });
    }

    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.body?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const fee = await HostelFeeMaster.findOneAndUpdate(
      { collegeKey, month },
      { collegeKey, month, monthlyFee: toNumber(monthlyFee) },
      { upsert: true, new: true, runValidators: true }
    );
    res.status(201).json(fee);
  } catch (error) {
    res.status(500).json({ message: "Failed to save hostel fee" });
  }
});

app.get("/api/hostel-fees", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const filter =
      req.user.role === "admin"
        ? req.query.collegeKey
          ? collegeMatch(req.query.collegeKey)
          : {}
        : collegeMatch(req.user.collegeKey);

    const data = await HostelFeeMaster.find(filter).sort({ month: 1 });
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: "Failed to load hostel fees" });
  }
});

app.post(
  "/api/hostel-attendance",
  authRequired,
  anyRoleRequired(BILLING_ROLES),
  async (req, res) => {
  try {
    const { pin, month, totalDays, daysStayed } = req.body;
    if (!pin || !month || !totalDays) {
      return res.status(400).json({ message: "pin, month, totalDays are required" });
    }

    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.body?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const student = await Student.findOne({ ...collegeMatch(collegeKey), pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const monthly = await HostelFeeMaster.findOne({ ...collegeMatch(collegeKey), month });
    if (!monthly) return res.status(404).json({ message: "Month not configured in hostel fee master" });

    const total = Math.max(1, toNumber(totalDays));
    const stayed = Math.max(0, Math.min(toNumber(daysStayed), total));
    const calculatedFee = Math.round((toNumber(monthly.monthlyFee) / total) * stayed);

    const attendance = await HostelAttendance.findOneAndUpdate(
      { collegeKey, pin, month },
      {
        collegeKey,
        pin,
        month,
        totalDays: total,
        daysStayed: stayed,
        calculatedFee
      },
      { upsert: true, new: true, runValidators: true }
    );

    res.status(201).json(attendance);
  } catch (error) {
    res.status(500).json({ message: "Failed to save hostel attendance" });
  }
  }
);

app.post(
  "/api/hostel-payments",
  authRequired,
  anyRoleRequired(BILLING_ROLES),
  async (req, res) => {
  try {
    const { date, pin, month, amountPaid, phone } = req.body;
    if (!pin || !month || !amountPaid) {
      return res.status(400).json({ message: "pin, month, amountPaid are required" });
    }

    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.body?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const student = await Student.findOne({ ...collegeMatch(collegeKey), pin });
    if (!student) return res.status(404).json({ message: "Student not found" });

    const payment = await HostelPayment.create({
      date: date ? new Date(date) : new Date(),
      collegeKey,
      pin,
      month,
      amountPaid: toNumber(amountPaid),
      phone: String(phone || "").trim()
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
  anyRoleRequired(BILLING_ROLES),
  async (req, res) => {
  try {
    const filter =
      req.user.role === "admin"
        ? req.query.collegeKey
          ? collegeMatch(req.query.collegeKey)
          : {}
        : collegeMatch(req.user.collegeKey);

    const students = await Student.find(filter).sort({ createdAt: -1 });
    const balances = await Promise.all(
      students.map((item) => computeStudentBalances(item.collegeKey || "default", item.pin))
    );
    res.json(balances.filter(Boolean));
  } catch (error) {
    res.status(500).json({ message: "Failed to load dashboard" });
  }
  }
);

app.get("/api/receipt/:pin", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.query?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const data = await computeStudentBalances(collegeKey, req.params.pin);
    if (!data) return res.status(404).json({ message: "Student not found" });

    res.json({
      generatedOn: new Date().toISOString(),
      ...data
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to build receipt" });
  }
});

app.get("/api/receipt/:pin/pdf", authRequired, anyRoleRequired(BILLING_ROLES), async (req, res) => {
  try {
    const pin = String(req.params.pin || "").trim();
    const collegeKey =
      req.user.role === "admin"
        ? normalizeCollegeKey(req.query?.collegeKey)
        : normalizeCollegeKey(req.user.collegeKey);

    const data = await computeStudentBalances(collegeKey, pin);
    if (!data) return res.status(404).json({ message: "Student not found" });

    const generatedOn = new Date();
    const totalBalance = toNumber(data.collegeBalance) + toNumber(data.hostelBalance);
    const kindRaw = String(req.query.kind || "").toLowerCase().trim();
    const kind =
      kindRaw === "receipt" || kindRaw === "balance" ? kindRaw : totalBalance > 0 ? "balance" : "receipt";

    const fileBase = kind === "balance" ? "balance_due" : "receipt";
    const filename = `${fileBase}_${pin}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    const doc = new PDFDocument({ size: "A4", margin: 50 });
    doc.pipe(res);

    doc.fontSize(18).text("College Billing System", { align: "left" });
    doc.moveDown(0.2);
    doc.fontSize(12).fillColor("#333").text(`Generated on: ${generatedOn.toLocaleString()}`);
    doc.moveDown();

    doc.fontSize(14).fillColor("#000").text(kind === "balance" ? "Balance Due" : "Receipt Summary");
    doc.moveDown();

    const lines = [
      `PIN: ${data.pin}`,
      `Name: ${data.name}`,
      `Course: ${data.course}`,
      data.phone ? `Phone: ${data.phone}` : null
    ].filter(Boolean);
    lines.forEach((line) => doc.fontSize(12).fillColor("#000").text(line));
    doc.moveDown();

    const money = (n) => Number(n || 0).toFixed(0);

    doc.fontSize(12).text(`College Total Fee: ${money(data.collegeTotalFee)}`);
    doc.text(`College Paid: ${money(data.collegePaid)}`);
    doc.text(`College Balance: ${money(data.collegeBalance)}`);
    doc.moveDown(0.5);
    doc.text(`Hostel Charged: ${money(data.hostelCharged)}`);
    doc.text(`Hostel Paid: ${money(data.hostelPaid)}`);
    doc.text(`Hostel Balance: ${money(data.hostelBalance)}`);
    doc.moveDown();

    if (kind === "balance") {
      doc.fontSize(14).text(`Total Due: ${money(totalBalance)}`);
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor("#333").text(
        "Please pay the remaining balance. If you have already paid, contact the office for verification."
      );
    } else {
      doc.fontSize(11).fillColor("#333").text(
        "This is a summary receipt. For detailed entries, refer to the system records."
      );
    }

    doc.end();
  } catch (error) {
    res.status(500).json({ message: "Failed to build receipt PDF" });
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
    const { email, name, role, password, active, collegeKey } = req.body || {};
    if (!email || !name || !role) {
      return res.status(400).json({ message: "email, name, role are required" });
    }
    const finalRole = normalizeRole(role);
    if (!USER_ROLES.includes(finalRole)) {
      return res
        .status(400)
        .json({ message: "role must be admin, principal, accountant, or staff" });
    }

    const finalCollegeKey = normalizeCollegeKey(collegeKey);

    if (finalRole === "principal") {
      const existingPrincipal = await User.findOne({
        role: "principal",
        ...collegeMatch(finalCollegeKey),
        email: { $ne: String(email).toLowerCase().trim() }
      });
      if (existingPrincipal) {
        return res.status(400).json({ message: `Principal already exists for college ${finalCollegeKey}` });
      }
    }

    const emailFinal = String(email).toLowerCase().trim();
    const existing = await User.findOne({ email: emailFinal });

    const passwordStr = String(password || "").trim();
    let temporaryPassword = null;

    const update = {
      collegeKey: finalCollegeKey,
      email: emailFinal,
      name: String(name).trim(),
      role: finalRole,
      active: active !== false
    };

    if (passwordStr) {
      update.passwordHash = await bcrypt.hash(passwordStr, 10);
      update.mustChangePassword = false;
    } else if (!existing) {
      if (finalRole === "admin") {
        return res.status(400).json({ message: "password is required for admin user" });
      }
      temporaryPassword = crypto.randomBytes(9).toString("base64url"); // ~12 chars
      update.passwordHash = await bcrypt.hash(temporaryPassword, 10);
      update.mustChangePassword = true;
    }

    const user = await User.findOneAndUpdate(
      { email: emailFinal },
      update,
      { upsert: true, new: true, runValidators: true }
    );
    res.status(201).json({ user: sanitizeUser(user), temporaryPassword });
  } catch (error) {
    res.status(500).json({ message: "Failed to save user" });
  }
});

app.post("/api/admin/users/:id/reset-password", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.role === "admin") {
      return res.status(400).json({ message: "Cannot reset password for admin user via this endpoint" });
    }

    const temporaryPassword = crypto.randomBytes(9).toString("base64url");
    user.passwordHash = await bcrypt.hash(temporaryPassword, 10);
    user.mustChangePassword = true;
    await user.save();

    res.json({ user: sanitizeUser(user), temporaryPassword });
  } catch (error) {
    res.status(500).json({ message: "Failed to reset password" });
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
        const rowRoleRaw = String(row.role || row.Role || "").toLowerCase().trim();
        const rowPassword = String(row.password || row.Password || "").trim();
        const rowActiveRaw = String(row.active || row.Active || "").trim();
        const rowCollegeKey = normalizeCollegeKey(row.collegeKey || row.college || row.College || row.college_name || "");

        if (!rowEmail || !rowName || !rowRoleRaw || !rowPassword) {
          errors.push({ row: i + 2, message: "Missing required fields (email,name,role,password)" });
          continue;
        }

        const finalRole = normalizeRole(rowRoleRaw);

        if (!USER_ROLES.includes(finalRole)) {
          errors.push({ row: i + 2, message: "Invalid role (admin/principal/accountant/staff)" });
          continue;
        }

        if (finalRole === "principal") {
          const existingPrincipal = await User.findOne({
            role: "principal",
            ...collegeMatch(rowCollegeKey),
            email: { $ne: rowEmail }
          });
          if (existingPrincipal) {
            errors.push({
              row: i + 2,
              message: `Principal already exists for college ${rowCollegeKey}`
            });
            continue;
          }
        }

        const passwordHash = await bcrypt.hash(String(rowPassword), 10);
        const active =
          rowActiveRaw === ""
            ? true
            : ["true", "1", "yes"].includes(String(rowActiveRaw).toLowerCase());

        const existing = await User.findOne({ email: rowEmail });
        const user = await User.findOneAndUpdate(
          { email: rowEmail },
          { collegeKey: rowCollegeKey, email: rowEmail, name: rowName, role: finalRole, passwordHash, active },
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
      "collegeKey,email,name,role,password,active\n" +
        "default,staff1@example.com,Staff One,staff,ChangeMe123!,true\n" +
        "default,accountant1@example.com,Accountant One,accountant,ChangeMe123!,true\n" +
        "default,principal1@example.com,Principal One,principal,ChangeMe123!,true\n" +
        "default,admin2@example.com,Second Admin,admin,ChangeMe123!,true\n"
    );
  } catch (error) {
    res.status(500).json({ message: "Failed to build template" });
  }
});

app.get("/api/admin/colleges", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const rows = await User.aggregate([
      {
        $project: {
          collegeKey: { $ifNull: ["$collegeKey", "default"] },
          role: 1,
          active: 1
        }
      },
      {
        $group: {
          _id: "$collegeKey",
          totalUsers: { $sum: 1 },
          activeUsers: { $sum: { $cond: ["$active", 1, 0] } },
          totalNonAdmin: { $sum: { $cond: [{ $ne: ["$role", "admin"] }, 1, 0] } },
          activeNonAdmin: {
            $sum: { $cond: [{ $and: ["$active", { $ne: ["$role", "admin"] }] }, 1, 0] }
          }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const colleges = rows.map((r) => ({
      collegeKey: r._id || "default",
      totalUsers: r.totalUsers || 0,
      activeUsers: r.activeUsers || 0,
      totalNonAdmin: r.totalNonAdmin || 0,
      activeNonAdmin: r.activeNonAdmin || 0,
      enabled: (r.totalNonAdmin || 0) === 0 ? true : (r.activeNonAdmin || 0) > 0
    }));

    res.json(colleges);
  } catch (error) {
    res.status(500).json({ message: "Failed to load colleges" });
  }
});

app.post("/api/admin/colleges/active", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const { collegeKey, active } = req.body || {};
    const finalCollegeKey = normalizeCollegeKey(collegeKey);
    if (typeof active !== "boolean") {
      return res.status(400).json({ message: "active must be boolean" });
    }

    const result = await User.updateMany(
      { ...collegeMatch(finalCollegeKey), role: { $ne: "admin" } },
      { $set: { active } }
    );

    res.json({
      collegeKey: finalCollegeKey,
      active,
      matched: result.matchedCount ?? result.n ?? 0,
      modified: result.modifiedCount ?? result.nModified ?? 0
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to update college users" });
  }
});

app.get("/api/student-imports/template", authRequired, anyRoleRequired(["admin", "principal"]), async (req, res) => {
  try {
    const csv =
      "pin,name,course,phone,hasHostel,collegeTotalFee\n" +
      "220001,Student Name,COMPUTER ENGINEERING,9876543210,true,12000\n";

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=\"students_template.csv\"");
    res.send(csv);
  } catch (error) {
    res.status(500).json({ message: "Failed to download template" });
  }
});

app.post(
  "/api/student-imports",
  authRequired,
  anyRoleRequired(["admin", "principal"]),
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "file is required" });

      const uploaderRole = String(req.user?.role || "").toLowerCase().trim();
      const autoApprove = uploaderRole === "admin";

      const importCollegeKey = autoApprove
        ? normalizeCollegeKey(req.body.collegeKey)
        : normalizeCollegeKey(req.user?.collegeKey);

      const rowsRaw = rowsFromUpload(req.file);
      if (!rowsRaw || rowsRaw.length === 0) return res.status(400).json({ message: "No rows found" });
      if (rowsRaw.length > 5000) return res.status(400).json({ message: "Too many rows (max 5000)" });

      const rows = [];
      const errors = [];

      for (let i = 0; i < rowsRaw.length; i++) {
        const row = rowsRaw[i] || {};
        const normalized = normalizeStudentRow(row);
        if (!normalized.pin || !normalized.name || !normalized.course || normalized.collegeTotalFee === null) {
          errors.push({
            row: i + 2,
            message: "Missing required fields (pin,name,course,collegeTotalFee)"
          });
          continue;
        }
        rows.push(normalized);
      }

      if (errors.length) return res.status(400).json({ message: "Invalid rows found", errors });

      const record = await StudentImport.create({
        collegeKey: importCollegeKey,
        status: autoApprove ? "approved" : "pending",
        uploadedBy: req.auth.sub,
        uploadedByEmail: String(req.auth.email || ""),
        uploadedByRole: uploaderRole,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        rowsCount: rows.length,
        rows
      });

      if (!autoApprove) {
        return res.status(201).json({
          importId: String(record._id),
          status: record.status,
          collegeKey: record.collegeKey,
          rows: rows.length
        });
      }

      const result = await importStudents(importCollegeKey, rows);
      record.result = result;
      record.decidedBy = req.auth.sub;
      record.decidedAt = new Date();
      await record.save();

      res.status(201).json({
        importId: String(record._id),
        status: record.status,
        collegeKey: record.collegeKey,
        result
      });
    } catch (error) {
      res.status(500).json({ message: "Student import failed" });
    }
  }
);

app.get("/api/student-imports/my", authRequired, anyRoleRequired(["principal"]), async (req, res) => {
  try {
    const records = await StudentImport.find({ uploadedBy: req.auth.sub })
      .select("-rows")
      .sort({ createdAt: -1 });
    res.json(records);
  } catch (error) {
    res.status(500).json({ message: "Failed to load imports" });
  }
});

app.get("/api/admin/student-imports", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const records = await StudentImport.find().select("-rows").sort({ createdAt: -1 });
    res.json(records);
  } catch (error) {
    res.status(500).json({ message: "Failed to load imports" });
  }
});

app.get("/api/admin/student-imports/:id", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const record = await StudentImport.findById(req.params.id);
    if (!record) return res.status(404).json({ message: "Import not found" });
    res.json({
      ...record.toObject(),
      rows: (record.rows || []).slice(0, 50)
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to load import" });
  }
});

app.post("/api/admin/student-imports/:id/approve", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const record = await StudentImport.findById(req.params.id);
    if (!record) return res.status(404).json({ message: "Import not found" });
    if (record.status !== "pending") {
      return res.status(400).json({ message: `Import is ${record.status}, cannot approve` });
    }
    if (!record.rows || record.rows.length === 0) {
      return res.status(400).json({ message: "Import has no rows" });
    }

    const result = await importStudents(record.collegeKey, record.rows);
    record.status = "approved";
    record.result = result;
    record.decidedBy = req.auth.sub;
    record.decidedAt = new Date();
    record.decisionNote = String(req.body?.note || "").trim();
    await record.save();

    res.json({ importId: String(record._id), status: record.status, result });
  } catch (error) {
    res.status(500).json({ message: "Approve failed" });
  }
});

app.post("/api/admin/student-imports/:id/reject", authRequired, roleRequired("admin"), async (req, res) => {
  try {
    const record = await StudentImport.findById(req.params.id);
    if (!record) return res.status(404).json({ message: "Import not found" });
    if (record.status !== "pending") {
      return res.status(400).json({ message: `Import is ${record.status}, cannot reject` });
    }
    record.status = "rejected";
    record.decidedBy = req.auth.sub;
    record.decidedAt = new Date();
    record.decisionNote = String(req.body?.note || "").trim();
    await record.save();
    res.json({ importId: String(record._id), status: record.status });
  } catch (error) {
    res.status(500).json({ message: "Reject failed" });
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
