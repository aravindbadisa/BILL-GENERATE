import { useEffect, useState } from "react";
import { branches, colleges as collegesMaster, normalizeCollegeCode } from "./data/collegeData";

const resolveApiBase = () => {
  const envUrl = String(import.meta.env.VITE_API_URL || "").trim();
  if (import.meta.env.DEV) return envUrl || "http://localhost:5000";
  if (envUrl && !/localhost|127\.0\.0\.1/i.test(envUrl)) return envUrl;
  return window.location.origin;
};

const API_BASE = resolveApiBase();
const TOKEN_KEY = "billing_token";

const initialStudent = { pin: "", name: "", course: "", phone: "", collegeTotalFee: "", hasHostel: false };
const initialCombinedPayment = {
  pin: "",
  phone: "",
  collegeAmountPaid: "",
  hostelAmountPaid: "",
  hostelMonth: "",
  hostelMonthName: "",
  hostelYear: ""
};

const HOSTEL_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const initialHostelFee = { month: "", monthlyFee: "" };
const initialAttendance = { pin: "", month: "", totalDays: "", daysStayed: "" };
const initialHostelPayment = { pin: "", month: "", amountPaid: "", phone: "" };
const initialLogin = { email: "", password: "" };
const initialCreateUser = {
  collegeKey: "default",
  email: "",
  name: "",
  role: "staff",
  password: "",
  active: "true"
};
const initialAdminStudent = {
  collegeKey: "",
  pin: "",
  name: "",
  course: "",
  phone: "",
  collegeTotalFee: ""
};

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [me, setMe] = useState(null);
  const [loginForm, setLoginForm] = useState(initialLogin);
  const [pwForm, setPwForm] = useState({ newPassword: "", confirmPassword: "" });

  const collegeDisplay = (() => {
    const code = normalizeCollegeCode(me?.collegeKey || "default");
    if (code === "default") return { code, name: "Default College" };
    const found = collegesMaster.find((c) => c.code === code);
    return { code, name: found ? found.name : "Unknown College" };
  })();

  const [students, setStudents] = useState([]);
  const [dashboard, setDashboard] = useState([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [combinedPaymentForm, setCombinedPaymentForm] = useState(initialCombinedPayment);
  const [hostelFeeForm, setHostelFeeForm] = useState(initialHostelFee);
  const [attendanceForm, setAttendanceForm] = useState(initialAttendance);
  const [hostelPaymentForm, setHostelPaymentForm] = useState(initialHostelPayment);
  const [receiptPin, setReceiptPin] = useState("");
  const [receiptData, setReceiptData] = useState(null);
  const [receiptPhone, setReceiptPhone] = useState("");
  const [receiptLoading, setReceiptLoading] = useState(false);
  const [pinSearch, setPinSearch] = useState("");
  const [lastPaymentReceipt, setLastPaymentReceipt] = useState(null);
  const [studentForm, setStudentForm] = useState(initialStudent);
  const [activeTab, setActiveTab] = useState("students");

  const hostelYearOptions = (() => {
    const now = new Date();
    const y = now.getFullYear();
    const years = [];
    for (let i = y - 1; i <= y + 6; i += 1) years.push(String(i));
    return years;
  })();

  const parseMonthYear = (value) => {
    const raw = String(value || "").trim();
    const m = raw.match(/^([A-Za-z]{3})-(\d{4})$/);
    if (!m) return { month: "", year: "" };
    return { month: m[1], year: m[2] };
  };

  const setMonthYearField = (setter, field, part, nextValue) => {
    setter((prev) => {
      const current = parseMonthYear(prev[field]);
      const month = part === "month" ? String(nextValue || "") : current.month;
      const year = part === "year" ? String(nextValue || "") : current.year;
      return { ...prev, [field]: month && year ? `${month}-${year}` : "" };
    });
  };

  const readResponseBody = async (res) => {
    const contentType = String(res.headers.get("content-type") || "").toLowerCase();
    if (contentType.includes("application/json")) {
      try {
        return { kind: "json", value: await res.json() };
      } catch {
        return { kind: "json", value: null };
      }
    }
    let text = "";
    try {
      text = await res.text();
    } catch {
      text = "";
    }
    return { kind: "text", value: text };
  };

  const errorFromResponse = (res, body) => {
    if (body?.kind === "json" && body.value && typeof body.value === "object") {
      const msg = body.value.message;
      if (typeof msg === "string" && msg.trim()) return msg.trim();
    }

    if (body?.kind === "text") {
      const text = String(body.value || "");
      if (/<!doctype/i.test(text) || /<html/i.test(text)) {
        return `API URL is wrong (frontend returned HTML). Fix frontend/.env: VITE_API_URL=http://localhost:5000 then restart frontend.`;
      }
      const firstLine = text.split(/\r?\n/)[0]?.trim();
      if (firstLine) return firstLine.slice(0, 160);
    }

    return `Request failed (HTTP ${res.status})`;
  };

  const callApi = async (path, method = "GET", body = null) => {
    const headers = {};
    if (body !== null) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    const options = { method, headers };
    if (body !== null) options.body = JSON.stringify(body);
    const res = await fetch(`${API_BASE}${path}`, options);
    const parsed = await readResponseBody(res);
    if (!res.ok) throw new Error(errorFromResponse(res, parsed));
    if (parsed.kind !== "json") throw new Error("Server returned non-JSON response");
    return parsed.value;
  };

  const uploadFileWithFields = async (path, file, fields) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const fd = new FormData();
    fd.append("file", file);
    Object.entries(fields || {}).forEach(([k, v]) => fd.append(k, String(v ?? "")));
    const res = await fetch(`${API_BASE}${path}`, { method: "POST", headers, body: fd });
    const parsed = await readResponseBody(res);
    if (!res.ok) throw new Error(errorFromResponse(res, parsed));
    if (parsed.kind !== "json") throw new Error("Server returned non-JSON response");
    return parsed.value;
  };

  const uploadFile = async (path, file) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_BASE}${path}`, { method: "POST", headers, body: fd });
    const parsed = await readResponseBody(res);
    if (!res.ok) throw new Error(errorFromResponse(res, parsed));
    if (parsed.kind !== "json") throw new Error("Server returned non-JSON response");
    return parsed.value;
  };

  const loadMe = async (nextToken) => {
    try {
      const data = await (async () => {
        const headers = {};
        if (nextToken) headers.Authorization = `Bearer ${nextToken}`;
        const res = await fetch(`${API_BASE}/api/auth/me`, { headers });
        const parsed = await readResponseBody(res);
        if (!res.ok) throw new Error(errorFromResponse(res, parsed));
        if (parsed.kind !== "json") throw new Error("Server returned non-JSON response");
        return parsed.value;
      })();
      setMe(data.user);
    } catch (e) {
      setMe(null);
      setToken("");
      localStorage.removeItem(TOKEN_KEY);
    }
  };

  const loadDashboard = async () => {
    try {
      const [studentData, dashboardData] = await Promise.all([
        callApi("/api/students"),
        callApi("/api/dashboard/students")
      ]);
      setStudents(studentData);
      setDashboard(dashboardData);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    if (token) loadMe(token);
  }, [token]);

  useEffect(() => {
    const root = document.documentElement;
    const theme = !me ? "login" : me.role === "admin" ? "admin" : "billing";
    root.dataset.theme = theme;
    return () => {
      delete root.dataset.theme;
    };
  }, [me]);

  const handleInput = (setter) => (e) => {
    setter((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const normalizeCollegeKeyField = (setter, fieldName) => () => {
    setter((prev) => {
      const next = { ...prev };
      next[fieldName] = normalizeCollegeCode(next[fieldName]);
      return next;
    });
  };

  const submitForm = async (path, body, reset) => {
    setMessage("");
    setError("");
    try {
      const resp = await callApi(path, "POST", body);
      setMessage("Saved successfully.");
      reset();
      await loadDashboard();

      // Keep the selected student's balances in sync after saving payments/attendance.
      const pin = String(receiptPin || "").trim();
      if (pin) await loadReceiptForPin(pin);

      if (resp && typeof resp === "object" && resp.receiptNo) {
        setLastPaymentReceipt({ receiptNo: resp.receiptNo, receiptKey: resp.receiptKey || "" });
      }
    } catch (e) {
      setError(e.message);
    }
  };

  const createStudent = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      if (!studentForm.pin || !studentForm.name || !studentForm.course) {
        throw new Error("PIN, Name, Course are required");
      }
      if (studentForm.collegeTotalFee === "" || studentForm.collegeTotalFee === null) {
        throw new Error("College Total Fee is required");
      }
      const payload = {
        pin: String(studentForm.pin || "").trim(),
        name: String(studentForm.name || "").trim(),
        course: String(studentForm.course || "").trim(),
        phone: String(studentForm.phone || "").trim(),
        collegeTotalFee: Number(studentForm.collegeTotalFee || 0),
        hasHostel: Boolean(studentForm.hasHostel)
      };
      await callApi("/api/student-submissions", "POST", payload);
      setMessage("Student submitted to admin for approval.");
      setStudentForm(initialStudent);
      await Promise.all([loadDashboard(), loadMyStudentImports()]);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const loadReceiptForPin = async (pinRaw) => {
    const pin = String(pinRaw || "").trim();
    if (!pin) return;
    setMessage("");
    setError("");
    setReceiptLoading(true);
    setReceiptData(null);
    try {
      const data = await callApi(`/api/receipt/${encodeURIComponent(pin)}`);
      setReceiptData(data);
      setReceiptPhone(data.phone || "");
    } catch (e) {
      setError(e.message);
    } finally {
      setReceiptLoading(false);
    }
  };

  const fetchReceipt = async () => loadReceiptForPin(receiptPin);

  const clearSelectedStudent = () => {
    setReceiptPin("");
    setReceiptData(null);
    setReceiptPhone("");
    setLastPaymentReceipt(null);
    setCombinedPaymentForm(initialCombinedPayment);
    setAttendanceForm(initialAttendance);
    setHostelPaymentForm(initialHostelPayment);
  };

  const resetBillingState = () => {
    setStudents([]);
    setDashboard([]);
    setPinSearch("");
    clearSelectedStudent();
  };

  useEffect(() => {
    const pin = String(receiptPin || "").trim();
    if (!pin) {
      setReceiptData(null);
      setReceiptPhone("");
      setReceiptLoading(false);
      setCombinedPaymentForm(initialCombinedPayment);
      setAttendanceForm(initialAttendance);
      setHostelPaymentForm(initialHostelPayment);
      return;
    }

    const t = setTimeout(() => {
      loadReceiptForPin(pin);
    }, 350);
    return () => clearTimeout(t);
  }, [receiptPin]);

  const showHostel =
    Boolean(receiptData) &&
    Boolean(
      receiptData.hasHostel ||
        Number(receiptData.hostelCharged || 0) > 0 ||
        Number(receiptData.hostelPaid || 0) > 0 ||
        Number(receiptData.hostelBalance || 0) > 0
    );

  const getTotalBalance = (item) =>
    Number(item?.collegeBalance || 0) + Number(item?.hostelBalance || 0);

  const balanceRows = dashboard.map((item) => ({
    ...item,
    totalBalance: getTotalBalance(item)
  }));
  const remainingBalance = balanceRows
    .filter((item) => item.totalBalance > 0)
    .sort((a, b) => b.totalBalance - a.totalBalance);
  const clearedBalance = balanceRows
    .filter((item) => item.totalBalance <= 0)
    .sort((a, b) => String(a.pin || "").localeCompare(String(b.pin || "")));


  useEffect(() => {
    if (!receiptData?.pin) return;
    setCombinedPaymentForm((p) => ({ ...p, pin: receiptData.pin }));
    setAttendanceForm((p) => ({ ...p, pin: receiptData.pin }));
    setHostelPaymentForm((p) => ({ ...p, pin: receiptData.pin }));
  }, [receiptData?.pin]);

  useEffect(() => {
    setCombinedPaymentForm((prev) => {
      const m = String(prev.hostelMonthName || "").trim();
      const y = String(prev.hostelYear || "").trim();
      const hostelMonth = m && y ? `${m}-${y}` : "";
      if (prev.hostelMonth === hostelMonth) return prev;
      return { ...prev, hostelMonth };
    });
  }, [combinedPaymentForm.hostelMonthName, combinedPaymentForm.hostelYear]);

  const downloadReceiptPdf = async (kind = "auto") => {
    setMessage("");
    setError("");
    try {
      if (!receiptPin) throw new Error("Enter PIN");
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const qs = kind && kind !== "auto" ? `?kind=${encodeURIComponent(kind)}` : "";
      const res = await fetch(`${API_BASE}/api/receipt/${encodeURIComponent(receiptPin)}/pdf${qs}`, {
        headers
      });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        throw new Error(json.message || "Failed to download PDF");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${kind === "balance" ? "balance_due" : "receipt"}_${receiptPin}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMessage("PDF downloaded.");
    } catch (e) {
      setError(e.message);
    }
  };

  const downloadPaymentReceiptPdf = async () => {
    setMessage("");
    setError("");
    try {
      const receiptNo = String(lastPaymentReceipt?.receiptNo || "").trim();
      if (!receiptNo) throw new Error("No payment receipt yet");
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const res = await fetch(`${API_BASE}/api/payment-receipts/${encodeURIComponent(receiptNo)}/pdf`, { headers });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        throw new Error(json.message || "Failed to download payment receipt PDF");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `payment_receipt_${receiptNo}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMessage("Payment receipt PDF downloaded.");
    } catch (e) {
      setError(e.message);
    }
  };

  const csvEscape = (value) => {
    const raw = String(value ?? "");
    if (/[\",\n]/.test(raw)) return `"${raw.replace(/\"/g, '""')}"`;
    return raw;
  };

  const toBalanceCsv = (rows) => {
    const headers = [
      "PIN",
      "Name",
      "Course",
      "College Total",
      "College Paid",
      "College Balance",
      "Hostel Charged",
      "Hostel Paid",
      "Hostel Balance",
      "Total Balance"
    ];
    const lines = rows.map((r) =>
      [
        r.pin,
        r.name,
        r.course,
        r.collegeTotalFee,
        r.collegePaid,
        r.collegeBalance,
        r.hostelCharged,
        r.hostelPaid,
        r.hostelBalance,
        r.totalBalance
      ]
        .map(csvEscape)
        .join(",")
    );
    return [headers.join(","), ...lines].join("\n");
  };

  const downloadBalanceCsv = (rows, filename) => {
    if (!rows || rows.length === 0) {
      setError("No rows to export");
      return;
    }
    const csv = toBalanceCsv(rows);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "students.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const downloadBalancePdf = (rows, title) => {
    if (!rows || rows.length === 0) {
      setError("No rows to export");
      return;
    }
    const safeTitle = String(title || "Students").replace(/[<>]/g, "");
    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${safeTitle}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #111827; }
    h2 { margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; }
    th { background: #f8fafc; }
  </style>
</head>
<body>
  <h2>${safeTitle}</h2>
  <table>
    <thead>
      <tr>
        <th>PIN</th>
        <th>Name</th>
        <th>Course</th>
        <th>College Total</th>
        <th>College Paid</th>
        <th>College Balance</th>
        <th>Hostel Charged</th>
        <th>Hostel Paid</th>
        <th>Hostel Balance</th>
        <th>Total Balance</th>
      </tr>
    </thead>
    <tbody>
      ${rows
        .map(
          (r) => `<tr>
            <td>${r.pin ?? ""}</td>
            <td>${r.name ?? ""}</td>
            <td>${r.course ?? ""}</td>
            <td>${r.collegeTotalFee ?? ""}</td>
            <td>${r.collegePaid ?? ""}</td>
            <td>${r.collegeBalance ?? ""}</td>
            <td>${r.hostelCharged ?? ""}</td>
            <td>${r.hostelPaid ?? ""}</td>
            <td>${r.hostelBalance ?? ""}</td>
            <td>${r.totalBalance ?? ""}</td>
          </tr>`
        )
        .join("\n")}
    </tbody>
  </table>
</body>
</html>`;
    const win = window.open("", "_blank", "noopener,noreferrer,width=900,height=700");
    if (!win) {
      setError("Popup blocked. Allow popups to download PDF.");
      return;
    }
    win.document.write(html);
    win.document.close();
    win.focus();
    win.print();
  };

  const canWhatsApp = ["principal", "admin"].includes(me?.role);
  const openWhatsApp = () => {
    setMessage("");
    setError("");
    if (!receiptData) {
      setError("Fetch receipt data first");
      return;
    }
    const raw = String(receiptPhone || "").trim();
    const phoneDigits = raw.replace(/[^\d]/g, "");
    if (!phoneDigits) {
      setError("Enter phone number (include country code if needed)");
      return;
    }
    const totalDue = Number(receiptData.collegeBalance || 0) + Number(receiptData.hostelBalance || 0);
    const text =
      totalDue > 0
        ? `Hello ${receiptData.name}, your remaining balance is College: ${receiptData.collegeBalance}, Hostel: ${receiptData.hostelBalance}, Total: ${totalDue}. Please pay the remaining amount.`
        : `Hello ${receiptData.name}, your receipt summary: College paid ${receiptData.collegePaid} / ${receiptData.collegeTotalFee}. Hostel balance ${receiptData.hostelBalance}.`;
    const url = `https://wa.me/${phoneDigits}?text=${encodeURIComponent(text)}`;
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const login = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      const data = await callApi("/api/auth/login", "POST", loginForm);
      resetBillingState();
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setMe(data.user);
      setLoginForm(initialLogin);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const changePassword = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      if (!pwForm.newPassword || pwForm.newPassword.length < 8) {
        throw new Error("Password must be at least 8 characters");
      }
      if (pwForm.newPassword !== pwForm.confirmPassword) {
        throw new Error("Passwords do not match");
      }
      const data = await callApi("/api/auth/change-password", "POST", { newPassword: pwForm.newPassword });
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setMe(data.user);
      setPwForm({ newPassword: "", confirmPassword: "" });
      setMessage("Password updated.");
    } catch (e2) {
      setError(e2.message);
    }
  };

  const logout = () => {
    resetBillingState();
    setMe(null);
    setToken("");
    localStorage.removeItem(TOKEN_KEY);
  };

  useEffect(() => {
    // If a different user logs in, clear any previous college data immediately.
    resetBillingState();
    if (me && !me.mustChangePassword) loadDashboard();
  }, [me?.id]);

  // Admin state
  const [users, setUsers] = useState([]);
  const [createUserForm, setCreateUserForm] = useState(initialCreateUser);
  const [importFile, setImportFile] = useState(null);
  const [colleges, setColleges] = useState([]);
  const [adminStudentForm, setAdminStudentForm] = useState(initialAdminStudent);
  const [studentImportFile, setStudentImportFile] = useState(null);
  const [adminStudentImportCollege, setAdminStudentImportCollege] = useState("");
  const [myStudentImports, setMyStudentImports] = useState([]);
  const [adminStudentImports, setAdminStudentImports] = useState([]);
  const [selectedImport, setSelectedImport] = useState(null);

  const isAdmin = me?.role === "admin";
  const isPrincipal = me?.role === "principal";

  const loadUsers = async () => {
    if (!isAdmin) return;
    try {
      const data = await callApi("/api/admin/users");
      setUsers(data);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    if (isAdmin) loadUsers();
  }, [isAdmin]);

  const loadColleges = async () => {
    if (!isAdmin) return;
    try {
      const data = await callApi("/api/admin/colleges");
      setColleges(data);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    if (isAdmin) loadColleges();
  }, [isAdmin]);

  const downloadStudentsTemplate = async () => {
    setMessage("");
    setError("");
    try {
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const res = await fetch(`${API_BASE}/api/student-imports/template`, { headers });
      if (!res.ok) {
        const parsed = await readResponseBody(res);
        throw new Error(errorFromResponse(res, parsed));
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "students_template.csv";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const submitStudentImport = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      if (!studentImportFile) throw new Error("Select a .xlsx or .csv file");
      if (isAdmin) {
        if (!adminStudentImportCollege) throw new Error("College Code is required for admin import");
        const result = await uploadFileWithFields(
          "/api/student-imports",
          studentImportFile,
          { collegeKey: adminStudentImportCollege }
        );
        setMessage(
          `Student import complete for college ${result.collegeKey}. created=${result.result?.created ?? 0} updated=${result.result?.updated ?? 0}`
        );
      } else {
        const result = await uploadFile("/api/student-imports", studentImportFile);
        setMessage(`Student import submitted. status=${result.status} rows=${result.rows}`);
      }
      setStudentImportFile(null);
      await Promise.all([loadMyStudentImports(), loadAdminStudentImports()]);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const loadMyStudentImports = async () => {
    if (!isPrincipal) return;
    try {
      const data = await callApi("/api/student-imports/my");
      setMyStudentImports(data);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    if (isPrincipal) loadMyStudentImports();
  }, [isPrincipal]);

  const loadAdminStudentImports = async () => {
    if (!isAdmin) return;
    try {
      const data = await callApi("/api/admin/student-imports");
      setAdminStudentImports(data);
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    if (isAdmin) loadAdminStudentImports();
  }, [isAdmin]);

  const openImportPreview = async (id) => {
    setMessage("");
    setError("");
    try {
      const data = await callApi(`/api/admin/student-imports/${encodeURIComponent(id)}`);
      setSelectedImport(data);
    } catch (e) {
      setError(e.message);
    }
  };

  const approveImport = async (id) => {
    setMessage("");
    setError("");
    try {
      const result = await callApi(`/api/admin/student-imports/${encodeURIComponent(id)}/approve`, "POST", {});
      setMessage(`Approved import. created=${result.result?.created ?? 0} updated=${result.result?.updated ?? 0}`);
      setSelectedImport(null);
      await loadAdminStudentImports();
    } catch (e) {
      setError(e.message);
    }
  };

  const rejectImport = async (id) => {
    setMessage("");
    setError("");
    try {
      await callApi(`/api/admin/student-imports/${encodeURIComponent(id)}/reject`, "POST", {});
      setMessage("Rejected import.");
      setSelectedImport(null);
      await loadAdminStudentImports();
    } catch (e) {
      setError(e.message);
    }
  };

  const createUser = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      const payload = {
        collegeKey: createUserForm.collegeKey,
        email: createUserForm.email,
        name: createUserForm.name,
        role: createUserForm.role,
        password: createUserForm.password,
        active: String(createUserForm.active).toLowerCase() !== "false"
      };
      if (String(payload.role).toLowerCase() === "admin" && !String(payload.password || "").trim()) {
        throw new Error("Password is required for admin user");
      }
      const result = await callApi("/api/admin/users", "POST", payload);
      const temp = result?.temporaryPassword ? ` Temporary password: ${result.temporaryPassword}` : "";
      setMessage(`User saved.${temp}`);
      setCreateUserForm(initialCreateUser);
      await Promise.all([loadUsers(), loadColleges()]);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const createStudentAsAdmin = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      if (!adminStudentForm.collegeKey) throw new Error("College Code is required");
      if (!adminStudentForm.pin || !adminStudentForm.name || !adminStudentForm.course) {
        throw new Error("PIN, Name, Course are required");
      }
      if (adminStudentForm.collegeTotalFee === "" || adminStudentForm.collegeTotalFee === null) {
        throw new Error("College Total Fee is required");
      }
      await callApi("/api/students", "POST", adminStudentForm);
      setMessage("Student saved.");
      setAdminStudentForm(initialAdminStudent);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const importUsers = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      if (!importFile) throw new Error("Select a .xlsx or .csv file");
      const result = await uploadFile("/api/admin/users/import", importFile);
      setMessage(`Import complete. created=${result.created} updated=${result.updated}`);
      if (result.errors?.length) {
        setError(`Some rows failed. First error: row ${result.errors[0].row}: ${result.errors[0].message}`);
      }
      setImportFile(null);
      await Promise.all([loadUsers(), loadColleges()]);
    } catch (e2) {
      setError(e2.message);
    }
  };

  const setCollegeActive = async (collegeKey, active) => {
    setMessage("");
    setError("");
    try {
      await callApi("/api/admin/colleges/active", "POST", { collegeKey, active });
      setMessage(`${active ? "Enabled" : "Disabled"} college: ${collegeKey}`);
      await loadColleges();
    } catch (e) {
      setError(e.message);
    }
  };

  const resetUserPassword = async (userId) => {
    setMessage("");
    setError("");
    try {
      const result = await callApi(`/api/admin/users/${encodeURIComponent(userId)}/reset-password`, "POST", {});
      const temp = result?.temporaryPassword ? ` Temporary password: ${result.temporaryPassword}` : "";
      setMessage(`Password reset.${temp}`);
      await loadUsers();
    } catch (e) {
      setError(e.message);
    }
  };

  const downloadTemplate = async () => {
    setMessage("");
    setError("");
    try {
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const res = await fetch(`${API_BASE}/api/admin/users/template`, { headers });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        throw new Error(json.message || "Failed to download template");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "users_template.csv";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e2) {
      setError(e2.message);
    }
  };

  if (!me) {
    return (
      <div className="page">
        <header className="hero">
          <h1>College Fee & Hostel Billing</h1>
          <p>Sign in to continue</p>
        </header>
        {error && <p className="error">{error}</p>}
        <section className="card">
          <h2>Login</h2>
          <form onSubmit={login}>
            <input
              name="email"
              type="email"
              placeholder="Email"
              value={loginForm.email}
              onChange={handleInput(setLoginForm)}
              required
            />
            <input
              name="password"
              type="password"
              placeholder="Password"
              value={loginForm.password}
              onChange={handleInput(setLoginForm)}
              required
            />
            <button type="submit">Login</button>
          </form>
        </section>
      </div>
    );
  }

  if (me.mustChangePassword) {
    return (
      <div className="page">
        <header className="hero">
          <h1>College Fee & Hostel Billing</h1>
          <p>Password setup required</p>
          <div className="topbar">
            <span className="badge">
              {me.name} ({me.role})
            </span>
            {me.role !== "admin" && (
              <span className="badge subtle">
                {collegeDisplay.code} - {collegeDisplay.name}
              </span>
            )}
            <button type="button" className="secondary" onClick={logout}>
              Logout
            </button>
          </div>
        </header>

        {message && <p className="success">{message}</p>}
        {error && <p className="error">{error}</p>}

        <section className="card">
          <h2>Set New Password</h2>
          <form onSubmit={changePassword}>
            <input
              name="newPassword"
              type="password"
              placeholder="New password (min 8 chars)"
              value={pwForm.newPassword}
              onChange={(e) => setPwForm((p) => ({ ...p, newPassword: e.target.value }))}
              required
            />
            <input
              name="confirmPassword"
              type="password"
              placeholder="Confirm password"
              value={pwForm.confirmPassword}
              onChange={(e) => setPwForm((p) => ({ ...p, confirmPassword: e.target.value }))}
              required
            />
            <button type="submit">Save Password</button>
          </form>
        </section>
      </div>
    );
  }

  return (
    <div className="page">
      <datalist id="collegeOptions">
        <option value="default">default</option>
        {collegesMaster.map((c) => (
          <option key={c.code} value={c.code}>
            {c.code} - {c.name}
          </option>
        ))}
      </datalist>
      <datalist id="courseOptions">
        {branches.map((b) => (
          <option key={b} value={b} />
        ))}
      </datalist>
      <header className="hero">
        <h1>College Fee & Hostel Billing</h1>
        <p>Fee collection, hostel billing, receipts & balances</p>
        <div className="topbar">
          <span className="badge">
            {me.name} ({me.role})
          </span>
          {me.role !== "admin" && (
            <span className="badge subtle">
              {collegeDisplay.code} - {collegeDisplay.name}
            </span>
          )}
          <button type="button" className="secondary" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      {message && <p className="success">{message}</p>}
      {error && <p className="error">{error}</p>}

      {isAdmin && (
        <section className="card grid">
          <div>
            <h2>Admin: Create User</h2>
            <form onSubmit={createUser}>
              <input
                name="collegeKey"
                placeholder="College Code (e.g. 008)"
                value={createUserForm.collegeKey}
                onChange={handleInput(setCreateUserForm)}
                onBlur={normalizeCollegeKeyField(setCreateUserForm, "collegeKey")}
                list="collegeOptions"
                required
              />
              <input name="email" type="email" placeholder="Email" value={createUserForm.email} onChange={handleInput(setCreateUserForm)} required />
              <input name="name" placeholder="Name" value={createUserForm.name} onChange={handleInput(setCreateUserForm)} required />
              <select name="role" value={createUserForm.role} onChange={handleInput(setCreateUserForm)}>
                <option value="staff">staff</option>
                <option value="accountant">accountant</option>
                <option value="principal">principal</option>
                <option value="admin">admin</option>
              </select>
              <input
                name="password"
                type="password"
                placeholder="Password (leave blank to auto-generate)"
                value={createUserForm.password}
                onChange={handleInput(setCreateUserForm)}
              />
              <select name="active" value={createUserForm.active} onChange={handleInput(setCreateUserForm)}>
                <option value="true">active</option>
                <option value="false">inactive</option>
              </select>
              <button type="submit">Save User</button>
            </form>
            <p className="hint">
              For `principal/accountant/staff`, you can leave password blank. Admin will get a temporary password to share, and user must set a new password at first login.
            </p>
          </div>

          <div>
            <h2>Admin: Import Users (Excel/CSV)</h2>
            <div className="inline">
              <button type="button" className="secondary" onClick={downloadTemplate}>
                Download Template CSV
              </button>
            </div>
            <form onSubmit={importUsers}>
              <input
                type="file"
                accept=".xlsx,.xls,.csv"
                onChange={(e) => setImportFile(e.target.files?.[0] || null)}
              />
              <button type="submit">Upload & Import</button>
            </form>
            <p className="hint">
              Columns required: `collegeKey,email,name,role,password` (optional `active`). Role must be `admin`, `principal`, `accountant`, or `staff`.
            </p>
          </div>

          <div>
            <h2>Admin: Add Student (Single)</h2>
            <form onSubmit={createStudentAsAdmin}>
              <input
                name="collegeKey"
                placeholder="College Code (e.g. 008)"
                value={adminStudentForm.collegeKey}
                onChange={handleInput(setAdminStudentForm)}
                onBlur={normalizeCollegeKeyField(setAdminStudentForm, "collegeKey")}
                list="collegeOptions"
                required
              />
              <input name="pin" placeholder="PIN" value={adminStudentForm.pin} onChange={handleInput(setAdminStudentForm)} required />
              <input name="name" placeholder="Name" value={adminStudentForm.name} onChange={handleInput(setAdminStudentForm)} required />
              <input
                name="course"
                placeholder="Course"
                value={adminStudentForm.course}
                onChange={handleInput(setAdminStudentForm)}
                list="courseOptions"
                required
              />
              <input name="phone" placeholder="Phone (optional)" value={adminStudentForm.phone} onChange={handleInput(setAdminStudentForm)} />
              <input
                name="collegeTotalFee"
                type="number"
                min="0"
                placeholder="College Total Fee"
                value={adminStudentForm.collegeTotalFee}
                onChange={handleInput(setAdminStudentForm)}
                required
              />
              <button type="submit">Save Student</button>
            </form>
            <p className="hint">
              Use this when you need to add one student manually (without Excel). Students cannot log in; this is only billing data.
            </p>
          </div>
        </section>
      )}


      {isAdmin && (
        <section className="card">
          <h2>Admin: Import Students (Excel/CSV)</h2>
          <div className="inline">
            <button type="button" className="secondary" onClick={downloadStudentsTemplate}>
              Download Students Template
            </button>
          </div>
          <form onSubmit={submitStudentImport}>
            <input
              placeholder="College Code (e.g. 008)"
              value={adminStudentImportCollege}
              onChange={(e) => setAdminStudentImportCollege(e.target.value)}
              onBlur={() => setAdminStudentImportCollege(normalizeCollegeCode(adminStudentImportCollege))}
              list="collegeOptions"
              required
            />
            <input
              type="file"
              accept=".xlsx,.xls,.csv"
              onChange={(e) => setStudentImportFile(e.target.files?.[0] || null)}
              required
            />
            <button type="submit">Upload & Import</button>
          </form>
          <p className="hint">Admin imports are auto-approved and directly create/update students.</p>
        </section>
      )}

      {isAdmin && (
        <section className="card">
          <h2>Admin: Pending Student Imports</h2>
          {adminStudentImports.length === 0 ? (
            <p>No imports.</p>
          ) : (
            <div className="tableWrap">
              <table style={{ minWidth: 960 }}>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>College</th>
                    <th>Uploaded By</th>
                    <th>File</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {adminStudentImports.map((r) => (
                    <tr key={String(r._id)}>
                      <td>{new Date(r.createdAt).toLocaleString()}</td>
                      <td>{r.collegeKey}</td>
                      <td>{r.uploadedByEmail}</td>
                      <td>{r.originalName}</td>
                      <td>
                        <span className={`statusPill ${r.status}`}>{r.status}</span>
                      </td>
                      <td>
                        <button type="button" className="secondary" onClick={() => openImportPreview(r._id)}>
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {selectedImport && (
            <div className="receipt" style={{ marginTop: 12 }}>
              <div className="inline" style={{ alignItems: "center" }}>
                <strong style={{ flex: 1 }}>
                  Preview: {selectedImport.originalName} ({selectedImport.collegeKey})
                </strong>
                <button type="button" className="secondary" onClick={() => setSelectedImport(null)}>
                  Close
                </button>
              </div>
              <p className="hint">
                Showing first {selectedImport.rows?.length || 0} rows (max 50). Status:{" "}
                <span className={`statusPill ${selectedImport.status}`}>{selectedImport.status}</span>
              </p>

              {selectedImport.rows?.length ? (
                <div className="tableWrap">
                  <table style={{ minWidth: 920 }}>
                    <thead>
                      <tr>
                        <th>PIN</th>
                        <th>Name</th>
                        <th>Course</th>
                        <th>Phone</th>
                        <th>Total Fee</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedImport.rows.map((row, idx) => (
                        <tr key={idx}>
                          <td>{row.pin}</td>
                          <td>{row.name}</td>
                          <td>{row.course}</td>
                          <td>{row.phone || "-"}</td>
                          <td>{row.collegeTotalFee}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p>No rows.</p>
              )}

              {selectedImport.status === "pending" && (
                <div className="inline" style={{ marginTop: 10 }}>
                  <button type="button" onClick={() => approveImport(selectedImport._id)}>
                    Approve
                  </button>
                  <button type="button" className="secondary" onClick={() => rejectImport(selectedImport._id)}>
                    Reject
                  </button>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {isAdmin && (
        <section className="card">
          <h2>Admin: Colleges (1-click login access)</h2>
          {colleges.length === 0 ? (
            <p>No colleges yet.</p>
          ) : (
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>College Code</th>
                    <th>Enabled</th>
                    <th>Active users</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {colleges.map((c) => (
                    <tr key={c.collegeKey}>
                      <td>{c.collegeKey}</td>
                      <td>{String(c.enabled)}</td>
                      <td>
                        {c.activeNonAdmin}/{c.totalNonAdmin} (non-admin)
                      </td>
                      <td>
                        {c.enabled ? (
                          <button
                            type="button"
                            className="secondary"
                            onClick={() => setCollegeActive(c.collegeKey, false)}
                          >
                            Disable
                          </button>
                        ) : (
                          <button type="button" onClick={() => setCollegeActive(c.collegeKey, true)}>
                            Enable
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="hint">
            Disable sets all non-admin users in that college to inactive (they cannot login). Enable sets them back to
            active.
          </p>
        </section>
      )}

      {isAdmin && (
        <section className="card">
          <h2>Admin: Users</h2>
          {users.length === 0 ? (
            <p>No users.</p>
          ) : (
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>College</th>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Role</th>
                    <th>Active</th>
                    <th>Password</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.collegeKey || "default"}</td>
                      <td>{u.email}</td>
                      <td>{u.name}</td>
                      <td>{u.role}</td>
                      <td>{String(u.active)}</td>
                      <td>{u.mustChangePassword ? "must set" : "set"}</td>
                      <td>
                        {u.role !== "admin" && (
                          <button type="button" className="secondary" onClick={() => resetUserPassword(u.id)}>
                            Reset Password
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {!isAdmin && (
        <>
          <div className="tabs">
            <button
              type="button"
              className={`tab ${activeTab === "students" ? "active" : ""}`}
              onClick={() => setActiveTab("students")}
            >
              Students
            </button>
            <button
              type="button"
              className={`tab ${activeTab === "workspace" ? "active" : ""}`}
              onClick={() => setActiveTab("workspace")}
            >
              Billing Workspace
            </button>
            <button
              type="button"
              className={`tab ${activeTab === "payment" ? "active" : ""}`}
              onClick={() => setActiveTab("payment")}
            >
              Payment
            </button>
          </div>

          {activeTab === "students" && (
            <>
              <section className="card grid">
                {isPrincipal && (
                  <div>
                    <h2>Add Student (Submit to Admin)</h2>
                    <form onSubmit={createStudent}>
                      <input name="pin" placeholder="PIN / Roll No" value={studentForm.pin} onChange={handleInput(setStudentForm)} required />
                      <input name="name" placeholder="Name" value={studentForm.name} onChange={handleInput(setStudentForm)} required />
                      <input
                        name="course"
                        placeholder="Course"
                        value={studentForm.course}
                        onChange={handleInput(setStudentForm)}
                        list="courseOptions"
                        required
                      />
                      <input name="phone" placeholder="Phone (optional)" value={studentForm.phone} onChange={handleInput(setStudentForm)} />
                      <input
                        name="collegeTotalFee"
                        type="number"
                        min="0"
                        placeholder="College Total Fee"
                        value={studentForm.collegeTotalFee}
                        onChange={handleInput(setStudentForm)}
                        required
                      />
                      <label className="inline" style={{ gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={Boolean(studentForm.hasHostel)}
                          onChange={(e) => setStudentForm((p) => ({ ...p, hasHostel: e.target.checked }))}
                        />
                        Hostel student
                      </label>
                      <button type="submit">Submit to Admin</button>
                    </form>
                  </div>
                )}

                <div>
                  <h2>Students With Balance</h2>
                  <div className="inline" style={{ marginBottom: 8 }}>
                    <button type="button" className="secondary" onClick={() => downloadBalanceCsv(remainingBalance, "students_with_balance.csv")}>
                      Download Excel (CSV)
                    </button>
                    <button type="button" className="secondary" onClick={() => downloadBalancePdf(remainingBalance, "Students With Balance") }>
                      Download PDF
                    </button>
                  </div>
                  {remainingBalance.length === 0 ? (
                    <p>No students with balance.</p>
                  ) : (
                    <div className="tableWrap">
                      <table>
                        <thead>
                          <tr>
                            <th>PIN</th>
                            <th>Name</th>
                            <th>Course</th>
                            <th>Total Balance</th>
                            <th>College Balance</th>
                            <th>Hostel Balance</th>
                          </tr>
                        </thead>
                        <tbody>
                          {remainingBalance.map((item) => (
                            <tr key={item.pin} onClick={() => setReceiptPin(item.pin)} style={{ cursor: "pointer" }}>
                              <td>{item.pin}</td>
                              <td>{item.name}</td>
                              <td>{item.course}</td>
                              <td>{item.totalBalance}</td>
                              <td>{item.collegeBalance}</td>
                              <td>{item.hostelBalance}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </section>

              <section className="card grid">
                <div>
                  <h2>Students Cleared</h2>
                  <div className="inline" style={{ marginBottom: 8 }}>
                    <button type="button" className="secondary" onClick={() => downloadBalanceCsv(clearedBalance, "students_cleared.csv")}>
                      Download Excel (CSV)
                    </button>
                    <button type="button" className="secondary" onClick={() => downloadBalancePdf(clearedBalance, "Students Cleared") }>
                      Download PDF
                    </button>
                  </div>
                  {clearedBalance.length === 0 ? (
                    <p>No cleared students yet.</p>
                  ) : (
                    <div className="tableWrap">
                      <table>
                        <thead>
                          <tr>
                            <th>PIN</th>
                            <th>Name</th>
                            <th>Course</th>
                            <th>Total Balance</th>
                          </tr>
                        </thead>
                        <tbody>
                          {clearedBalance.map((item) => (
                            <tr key={item.pin} onClick={() => setReceiptPin(item.pin)} style={{ cursor: "pointer" }}>
                              <td>{item.pin}</td>
                              <td>{item.name}</td>
                              <td>{item.course}</td>
                              <td>{item.totalBalance}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                <div>
                  <h2>All Students</h2>
                  {students.length === 0 ? (
                    <p>No student records.</p>
                  ) : (
                    <ul>
                      {students.map((s) => (
                        <li key={s._id}>
                          {s.pin} | {s.name} | {s.course}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </section>

              {isPrincipal && (
                <section className="card">
                  <h2>Principal: Submit Students (Excel/CSV)</h2>
                  <div className="inline">
                    <button type="button" className="secondary" onClick={downloadStudentsTemplate}>
                      Download Students Template
                    </button>
                  </div>
                  <form onSubmit={submitStudentImport}>
                    <input
                      type="file"
                      accept=".xlsx,.xls,.csv"
                      onChange={(e) => setStudentImportFile(e.target.files?.[0] || null)}
                      required
                    />
                    <button type="submit">Upload & Submit to Admin</button>
                  </form>
                  <p className="hint">
                    Admin will review and approve. After approval, students will be created in your college database.
                  </p>

                  {myStudentImports.length > 0 && (
                    <div className="tableWrap" style={{ marginTop: 12 }}>
                      <table style={{ minWidth: 720 }}>
                        <thead>
                          <tr>
                            <th>Date</th>
                            <th>File</th>
                            <th>Status</th>
                            <th>Rows</th>
                            <th>Note</th>
                          </tr>
                        </thead>
                        <tbody>
                          {myStudentImports.map((r) => (
                            <tr key={String(r._id)}>
                              <td>{new Date(r.createdAt).toLocaleString()}</td>
                              <td>{r.originalName}</td>
                              <td>
                                <span className={`statusPill ${r.status}`}>{r.status}</span>
                              </td>
                              <td>{(r.rowsCount ?? r.rows?.length) || "-"}</td>
                              <td>{r.decisionNote || "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </section>
              )}
            </>
          )}

          {activeTab === "workspace" && (
            <>
              <section className="card">
                <h2>Billing Workspace</h2>
                <div className="grid">
                  <div>
                    <h3>Live Student Dashboard</h3>
                    <div className="inline" style={{ marginBottom: 8 }}>
                      <input
                        value={pinSearch}
                        onChange={(e) => setPinSearch(e.target.value)}
                        placeholder="Search by PIN (leave empty to show all)"
                      />
                    </div>
                    {dashboard.length === 0 ? (
                      <p>No students yet.</p>
                    ) : (
                      <div className="tableWrap">
                        <table>
                          <thead>
                            <tr>
                              <th>PIN</th>
                              <th>Name</th>
                              <th>Course</th>
                              <th>College Total</th>
                              <th>College Paid</th>
                              <th>College Balance</th>
                              <th>Hostel Charged</th>
                              <th>Hostel Paid</th>
                              <th>Hostel Balance</th>
                            </tr>
                          </thead>
                          <tbody>
                            {dashboard
                              .filter((item) => {
                                const q = String(pinSearch || "").trim();
                                if (!q) return true;
                                return String(item.pin || "").includes(q);
                              })
                              .map((item) => (
                                <tr key={item.pin} style={{ cursor: "pointer" }} onClick={() => setReceiptPin(item.pin)}>
                                  <td>{item.pin}</td>
                                  <td>{item.name}</td>
                                  <td>{item.course}</td>
                                  <td>{item.collegeTotalFee}</td>
                                  <td>{item.collegePaid}</td>
                                  <td>{item.collegeBalance}</td>
                                  <td>{item.hostelCharged}</td>
                                  <td>{item.hostelPaid}</td>
                                  <td>{item.hostelBalance}</td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  <div>
                    <h3>Hostel Fee Master</h3>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        submitForm("/api/hostel-fees", hostelFeeForm, () => setHostelFeeForm(initialHostelFee));
                      }}
                    >
                      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
                        <div>
                          <label className="hint" style={{ marginTop: 0 }}>Month</label>
                          <select
                            value={parseMonthYear(hostelFeeForm.month).month}
                            onChange={(e) => setMonthYearField(setHostelFeeForm, "month", "month", e.target.value)}
                          >
                            <option value="">Select month</option>
                            {HOSTEL_MONTHS.map((m) => (
                              <option key={m} value={m}>{m}</option>
                            ))}
                          </select>
                        </div>
                        <div>
                          <label className="hint" style={{ marginTop: 0 }}>Year</label>
                          <select
                            value={parseMonthYear(hostelFeeForm.month).year}
                            onChange={(e) => setMonthYearField(setHostelFeeForm, "month", "year", e.target.value)}
                          >
                            <option value="">Select year</option>
                            {hostelYearOptions.map((y) => (
                              <option key={y} value={y}>{y}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                      <input
                        name="monthlyFee"
                        type="number"
                        min="0"
                        placeholder="Monthly Fee"
                        value={hostelFeeForm.monthlyFee}
                        onChange={handleInput(setHostelFeeForm)}
                        required
                      />
                      <button type="submit">Save Month Fee</button>
                    </form>
                    <p className="hint" style={{ marginTop: 8 }}>
                      Set hostel monthly fee first. Attendance is available only for hostel students.
                    </p>
                  </div>

                  <div>
                    <h3>Hostel Attendance</h3>
                    {!showHostel ? (
                      <p className="hint" style={{ marginTop: 8 }}>
                        Select a hostel student (enable “Hostel student” in receipt lookup) to add attendance.
                      </p>
                    ) : (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          submitForm("/api/hostel-attendance", attendanceForm, () =>
                            setAttendanceForm((p) => ({ ...initialAttendance, pin: receiptData?.pin || "" }))
                          );
                        }}
                      >
                        <input name="pin" placeholder="PIN" value={attendanceForm.pin} readOnly />
                        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
                          <div>
                            <label className="hint" style={{ marginTop: 0 }}>Month</label>
                            <select
                              value={parseMonthYear(attendanceForm.month).month}
                              onChange={(e) => setMonthYearField(setAttendanceForm, "month", "month", e.target.value)}
                            >
                              <option value="">Select month</option>
                              {HOSTEL_MONTHS.map((m) => (
                                <option key={m} value={m}>{m}</option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label className="hint" style={{ marginTop: 0 }}>Year</label>
                            <select
                              value={parseMonthYear(attendanceForm.month).year}
                              onChange={(e) => setMonthYearField(setAttendanceForm, "month", "year", e.target.value)}
                            >
                              <option value="">Select year</option>
                              {hostelYearOptions.map((y) => (
                                <option key={y} value={y}>{y}</option>
                              ))}
                            </select>
                          </div>
                        </div>
                        <input
                          name="totalDays"
                          type="number"
                          min="1"
                          placeholder="Total Days in Month"
                          value={attendanceForm.totalDays}
                          onChange={handleInput(setAttendanceForm)}
                          required
                        />
                        <input
                          name="daysStayed"
                          type="number"
                          min="0"
                          placeholder="Days Stayed"
                          value={attendanceForm.daysStayed}
                          onChange={handleInput(setAttendanceForm)}
                          required
                        />
                        <button type="submit" disabled={!receiptData?.pin}>Add Attendance</button>
                        {!receiptData?.pin && <p className="hint">Select a student PIN above first.</p>}
                      </form>
                    )}
                  </div>
                </div>
              </section>
            </>
          )}

          {activeTab === "payment" && (
            <>
              <section className="card grid">
                <div>
                  <h2>Student & Receipt Lookup (Roll No)</h2>
                  <div className="inline">
                    <input
                      value={receiptPin}
                      onChange={(e) => setReceiptPin(e.target.value)}
                      placeholder="Enter roll no / PIN"
                    />
                    <button type="button" className="secondary" onClick={clearSelectedStudent}>
                      Clear
                    </button>
                  </div>

                  {receiptLoading ? (
                    <p className="hint" style={{ marginTop: 10 }}>
                      Loading student...
                    </p>
                  ) : receiptData ? (
                    <div className="receipt" style={{ marginTop: 10 }}>
                      <p><strong>College:</strong> {(receiptData.collegeKey || "default")} - {(receiptData.collegeName || "Unknown College")}</p>
                      <p><strong>PIN:</strong> {receiptData.pin}</p>
                      <p><strong>Name:</strong> {receiptData.name}</p>
                      <p><strong>Course:</strong> {receiptData.course}</p>
                      <p><strong>Phone:</strong> {receiptData.phone || "-"}</p>
                      <p><strong>Receipt Key:</strong> {receiptData.receiptKey || "-"}</p>
                      <p><strong>College Balance:</strong> {receiptData.collegeBalance}</p>
                      <p><strong>Hostel Student:</strong> {receiptData.hasHostel ? "Yes" : "No"}</p>
                      {showHostel ? (
                        <p><strong>Hostel Balance:</strong> {receiptData.hostelBalance}</p>
                      ) : (
                        <p className="hint">This student is college-only (no hostel).</p>
                      )}
                      <p className="hint" style={{ marginTop: 6 }}>
                        Generated: {receiptData.generatedOn ? new Date(receiptData.generatedOn).toLocaleString() : "-"}
                      </p>
                    </div>
                  ) : (
                    <p className="hint" style={{ marginTop: 10 }}>
                      Search by roll no / PIN to view receipts.
                    </p>
                  )}
                </div>

                <div>
                  <h2>Payment (College + Hostel)</h2>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      submitForm("/api/payments", combinedPaymentForm, () =>
                        setCombinedPaymentForm((p) => ({ ...initialCombinedPayment, pin: receiptData?.pin || "" }))
                      );
                    }}
                  >
                    <input name="pin" placeholder="PIN (select student first)" value={combinedPaymentForm.pin} readOnly />
                    <input
                      name="phone"
                      placeholder="Phone (optional)"
                      value={combinedPaymentForm.phone}
                      onChange={handleInput(setCombinedPaymentForm)}
                    />

                    <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
                      <div>
                        <label className="hint" style={{ marginTop: 0 }}>College Amount Paid</label>
                        <input
                          name="collegeAmountPaid"
                          type="number"
                          min="0"
                          placeholder="0"
                          value={combinedPaymentForm.collegeAmountPaid}
                          onChange={handleInput(setCombinedPaymentForm)}
                        />
                      </div>
                      <div>
                        <label className="hint" style={{ marginTop: 0 }}>Hostel Amount Paid</label>
                        <input
                          name="hostelAmountPaid"
                          type="number"
                          min="0"
                          placeholder="0"
                          value={combinedPaymentForm.hostelAmountPaid}
                          onChange={handleInput(setCombinedPaymentForm)}
                          disabled={!showHostel}
                        />
                      </div>
                    </div>

                    <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
                      <div>
                        <label className="hint" style={{ marginTop: 0 }}>Hostel Month</label>
                        <select
                          name="hostelMonthName"
                          value={combinedPaymentForm.hostelMonthName}
                          onChange={handleInput(setCombinedPaymentForm)}
                          disabled={!showHostel}
                        >
                          <option value="">Select month</option>
                          {HOSTEL_MONTHS.map((m) => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="hint" style={{ marginTop: 0 }}>Hostel Year</label>
                        <select
                          name="hostelYear"
                          value={combinedPaymentForm.hostelYear}
                          onChange={handleInput(setCombinedPaymentForm)}
                          disabled={!showHostel}
                        >
                          <option value="">Select year</option>
                          {hostelYearOptions.map((y) => (
                            <option key={y} value={y}>{y}</option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <button type="submit" disabled={!receiptData?.pin}>Save Payment & Generate Receipt</button>
                    {!receiptData?.pin && <p className="hint">Select a student PIN above first.</p>}
                    {!showHostel && (
                      <p className="hint">
                        Hostel fields are disabled because this student is not marked as a hostel student.
                      </p>
                    )}

                    <div className="inline" style={{ marginTop: 10 }}>
                      <input
                        value={receiptPhone}
                        onChange={(e) => setReceiptPhone(e.target.value)}
                        placeholder="WhatsApp phone (optional)"
                      />
                      <button type="button" className="secondary" onClick={() => downloadReceiptPdf("auto")} disabled={!receiptData?.pin}>
                        Download PDF
                      </button>
                      <button type="button" className="secondary" onClick={downloadPaymentReceiptPdf} disabled={!lastPaymentReceipt?.receiptNo}>
                        Payment Receipt PDF
                      </button>
                      {canWhatsApp && (
                        <button type="button" onClick={openWhatsApp} disabled={!receiptData?.pin}>
                          WhatsApp Message
                        </button>
                      )}
                    </div>

                    {lastPaymentReceipt?.receiptNo && (
                      <p className="hint" style={{ marginTop: 8 }}>
                        Latest Payment Receipt: <b>{lastPaymentReceipt.receiptNo}</b>
                        {lastPaymentReceipt.receiptKey ? ` (Key: ${lastPaymentReceipt.receiptKey})` : ""}
                      </p>
                    )}
                    {canWhatsApp && (
                      <p className="hint" style={{ marginTop: 6 }}>
                        WhatsApp can’t auto-attach the PDF; download it and attach manually.
                      </p>
                    )}
                  </form>
                </div>
              </section>
            </>
          )}
        </>
      )}

    </div>
  );
}
