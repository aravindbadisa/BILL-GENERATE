import { useEffect, useState } from "react";
import { branches, colleges as collegesMaster, normalizeCollegeCode } from "./data/collegeData";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000";
const TOKEN_KEY = "billing_token";

const initialStudent = { pin: "", name: "", course: "", phone: "", collegeTotalFee: "" };
const initialCollegePayment = { pin: "", amountPaid: "", phone: "" };
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

  const [students, setStudents] = useState([]);
  const [dashboard, setDashboard] = useState([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [studentForm, setStudentForm] = useState(initialStudent);
  const [collegePaymentForm, setCollegePaymentForm] = useState(initialCollegePayment);
  const [hostelFeeForm, setHostelFeeForm] = useState(initialHostelFee);
  const [attendanceForm, setAttendanceForm] = useState(initialAttendance);
  const [hostelPaymentForm, setHostelPaymentForm] = useState(initialHostelPayment);
  const [receiptPin, setReceiptPin] = useState("");
  const [receiptData, setReceiptData] = useState(null);
  const [receiptPhone, setReceiptPhone] = useState("");

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
      await callApi(path, "POST", body);
      setMessage("Saved successfully.");
      reset();
      await loadDashboard();
    } catch (e) {
      setError(e.message);
    }
  };

  const fetchReceipt = async () => {
    setMessage("");
    setError("");
    setReceiptData(null);
    try {
      const data = await callApi(`/api/receipt/${receiptPin}`);
      setReceiptData(data);
      setReceiptPhone(data.phone || "");
    } catch (e) {
      setError(e.message);
    }
  };

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
    setMe(null);
    setToken("");
    localStorage.removeItem(TOKEN_KEY);
  };

  useEffect(() => {
    if (me && !me.mustChangePassword) loadDashboard();
  }, [me]);

  // Admin state
  const [users, setUsers] = useState([]);
  const [createUserForm, setCreateUserForm] = useState(initialCreateUser);
  const [importFile, setImportFile] = useState(null);
  const [colleges, setColleges] = useState([]);
  const [adminStudentForm, setAdminStudentForm] = useState(initialAdminStudent);

  const isAdmin = me?.role === "admin";

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
          <h1>College Billing System</h1>
          <p>Login required</p>
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
          <p className="hint">
            First run: set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in backend `.env` to seed admin.
          </p>
        </section>
      </div>
    );
  }

  if (me.mustChangePassword) {
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
          <h1>College Billing System</h1>
          <p>Password setup required</p>
          <div className="topbar">
            <span className="badge">
              {me.name} ({me.role})
            </span>
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
          <p className="hint">
            This account was created by admin. Set your own password to continue.
          </p>
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
        <h1>College Billing System</h1>
        <p>Built from your Excel structure: fees, payments, attendance, balances, receipt</p>
        <div className="topbar">
          <span className="badge">
            {me.name} ({me.role})
          </span>
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
        <section className="card grid">
        <div>
          <h2>Student Master</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitForm("/api/students", studentForm, () => setStudentForm(initialStudent));
            }}
          >
            <input name="pin" placeholder="PIN" value={studentForm.pin} onChange={handleInput(setStudentForm)} required />
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
            <button type="submit">Save Student</button>
          </form>
        </div>

        <div>
          <h2>College Payment</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitForm("/api/college-payments", collegePaymentForm, () =>
                setCollegePaymentForm(initialCollegePayment)
              );
            }}
          >
            <input name="pin" placeholder="PIN" value={collegePaymentForm.pin} onChange={handleInput(setCollegePaymentForm)} required />
            <input name="phone" placeholder="Phone (optional)" value={collegePaymentForm.phone} onChange={handleInput(setCollegePaymentForm)} />
            <input
              name="amountPaid"
              type="number"
              min="1"
              placeholder="Amount Paid"
              value={collegePaymentForm.amountPaid}
              onChange={handleInput(setCollegePaymentForm)}
              required
            />
            <button type="submit">Add College Payment</button>
          </form>
        </div>
      </section>

      <section className="card grid">
        <div>
          <h2>Hostel Fee Master</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitForm("/api/hostel-fees", hostelFeeForm, () => setHostelFeeForm(initialHostelFee));
            }}
          >
            <input name="month" placeholder="Month (e.g. Jan-2026)" value={hostelFeeForm.month} onChange={handleInput(setHostelFeeForm)} required />
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
        </div>

        <div>
          <h2>Hostel Attendance</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitForm("/api/hostel-attendance", attendanceForm, () => setAttendanceForm(initialAttendance));
            }}
          >
            <input name="pin" placeholder="PIN" value={attendanceForm.pin} onChange={handleInput(setAttendanceForm)} required />
            <input name="month" placeholder="Month (same as fee master)" value={attendanceForm.month} onChange={handleInput(setAttendanceForm)} required />
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
            <button type="submit">Add Attendance</button>
          </form>
        </div>
      </section>

      <section className="card grid">
        <div>
          <h2>Hostel Payment</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitForm("/api/hostel-payments", hostelPaymentForm, () =>
                setHostelPaymentForm(initialHostelPayment)
              );
            }}
          >
            <input name="pin" placeholder="PIN" value={hostelPaymentForm.pin} onChange={handleInput(setHostelPaymentForm)} required />
            <input name="month" placeholder="Month" value={hostelPaymentForm.month} onChange={handleInput(setHostelPaymentForm)} required />
            <input name="phone" placeholder="Phone (optional)" value={hostelPaymentForm.phone} onChange={handleInput(setHostelPaymentForm)} />
            <input
              name="amountPaid"
              type="number"
              min="1"
              placeholder="Amount Paid"
              value={hostelPaymentForm.amountPaid}
              onChange={handleInput(setHostelPaymentForm)}
              required
            />
            <button type="submit">Add Hostel Payment</button>
          </form>
        </div>

        <div>
          <h2>Receipt Lookup</h2>
          <div className="inline">
            <input value={receiptPin} onChange={(e) => setReceiptPin(e.target.value)} placeholder="Enter PIN" />
            <button type="button" onClick={fetchReceipt}>Get Receipt Data</button>
          </div>
          <div className="inline" style={{ marginTop: 8 }}>
            <input
              value={receiptPhone}
              onChange={(e) => setReceiptPhone(e.target.value)}
              placeholder="WhatsApp phone (optional)"
            />
            <button type="button" className="secondary" onClick={() => downloadReceiptPdf("auto")}>
              Download PDF
            </button>
            {canWhatsApp && (
              <button type="button" onClick={openWhatsApp}>
                WhatsApp Message
              </button>
            )}
          </div>
          {receiptData && (
            <div className="receipt">
              <p><strong>Name:</strong> {receiptData.name}</p>
              <p><strong>Course:</strong> {receiptData.course}</p>
              <p><strong>Phone:</strong> {receiptData.phone || "-"}</p>
              <p><strong>College Total:</strong> {receiptData.collegeTotalFee}</p>
              <p><strong>College Paid:</strong> {receiptData.collegePaid}</p>
              <p><strong>College Balance:</strong> {receiptData.collegeBalance}</p>
              <p><strong>Hostel Balance:</strong> {receiptData.hostelBalance}</p>
              {canWhatsApp && (
                <p className="hint">WhatsApp can’t auto-attach the PDF; download it and attach manually.</p>
              )}
            </div>
          )}
        </div>
      </section>

      <section className="card">
        <h2>Live Student Dashboard</h2>
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
                {dashboard.map((item) => (
                  <tr key={item.pin}>
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
      </section>

      <section className="card">
        <h2>Students</h2>
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
      </section>
        </>
      )}
    </div>
  );
}
