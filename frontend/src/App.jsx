import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000";
const TOKEN_KEY = "billing_token";

const initialStudent = { pin: "", name: "", course: "", collegeTotalFee: "" };
const initialCollegePayment = { date: "", pin: "", amountPaid: "" };
const initialHostelFee = { month: "", monthlyFee: "" };
const initialAttendance = { pin: "", month: "", totalDays: "", daysStayed: "" };
const initialHostelPayment = { date: "", pin: "", month: "", amountPaid: "" };
const initialLogin = { email: "", password: "" };
const initialCreateUser = { email: "", name: "", role: "staff", password: "", active: "true" };

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [me, setMe] = useState(null);
  const [loginForm, setLoginForm] = useState(initialLogin);

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

  const callApi = async (path, method = "GET", body = null) => {
    const headers = {};
    if (body !== null) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    const options = { method, headers };
    if (body !== null) options.body = JSON.stringify(body);
    const res = await fetch(`${API_BASE}${path}`, options);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Request failed");
    return data;
  };

  const uploadFile = async (path, file) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_BASE}${path}`, { method: "POST", headers, body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Upload failed");
    return data;
  };

  const loadMe = async (nextToken) => {
    try {
      const data = await (async () => {
        const headers = {};
        if (nextToken) headers.Authorization = `Bearer ${nextToken}`;
        const res = await fetch(`${API_BASE}/api/auth/me`, { headers });
        const json = await res.json();
        if (!res.ok) throw new Error(json.message || "Unauthorized");
        return json;
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

  const handleInput = (setter) => (e) => {
    setter((prev) => ({ ...prev, [e.target.name]: e.target.value }));
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
    } catch (e) {
      setError(e.message);
    }
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

  const logout = () => {
    setMe(null);
    setToken("");
    localStorage.removeItem(TOKEN_KEY);
  };

  useEffect(() => {
    if (me) loadDashboard();
  }, [me]);

  // Admin state
  const [users, setUsers] = useState([]);
  const [createUserForm, setCreateUserForm] = useState(initialCreateUser);
  const [importFile, setImportFile] = useState(null);

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

  const createUser = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");
    try {
      const payload = {
        email: createUserForm.email,
        name: createUserForm.name,
        role: createUserForm.role,
        password: createUserForm.password,
        active: String(createUserForm.active).toLowerCase() !== "false"
      };
      await callApi("/api/admin/users", "POST", payload);
      setMessage("User saved.");
      setCreateUserForm(initialCreateUser);
      await loadUsers();
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
      await loadUsers();
    } catch (e2) {
      setError(e2.message);
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

  return (
    <div className="page">
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
              <input name="email" type="email" placeholder="Email" value={createUserForm.email} onChange={handleInput(setCreateUserForm)} required />
              <input name="name" placeholder="Name" value={createUserForm.name} onChange={handleInput(setCreateUserForm)} required />
              <select name="role" value={createUserForm.role} onChange={handleInput(setCreateUserForm)}>
                <option value="staff">staff</option>
                <option value="accountant">accountant</option>
                <option value="principal">principal</option>
                <option value="admin">admin</option>
              </select>
              <input name="password" type="password" placeholder="Password" value={createUserForm.password} onChange={handleInput(setCreateUserForm)} required />
              <select name="active" value={createUserForm.active} onChange={handleInput(setCreateUserForm)}>
                <option value="true">active</option>
                <option value="false">inactive</option>
              </select>
              <button type="submit">Save User</button>
            </form>
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
              Columns required: `email,name,role,password` (optional `active`). Role must be `admin`, `principal`, `accountant`, or `staff`.
            </p>
          </div>
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
                    <th>Email</th>
                    <th>Name</th>
                    <th>Role</th>
                    <th>Active</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.email}</td>
                      <td>{u.name}</td>
                      <td>{u.role}</td>
                      <td>{String(u.active)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

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
            <input name="course" placeholder="Course" value={studentForm.course} onChange={handleInput(setStudentForm)} required />
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
            <input name="date" type="date" value={collegePaymentForm.date} onChange={handleInput(setCollegePaymentForm)} required />
            <input name="pin" placeholder="PIN" value={collegePaymentForm.pin} onChange={handleInput(setCollegePaymentForm)} required />
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
            <input name="date" type="date" value={hostelPaymentForm.date} onChange={handleInput(setHostelPaymentForm)} required />
            <input name="pin" placeholder="PIN" value={hostelPaymentForm.pin} onChange={handleInput(setHostelPaymentForm)} required />
            <input name="month" placeholder="Month" value={hostelPaymentForm.month} onChange={handleInput(setHostelPaymentForm)} required />
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
          {receiptData && (
            <div className="receipt">
              <p><strong>Name:</strong> {receiptData.name}</p>
              <p><strong>Course:</strong> {receiptData.course}</p>
              <p><strong>College Total:</strong> {receiptData.collegeTotalFee}</p>
              <p><strong>College Paid:</strong> {receiptData.collegePaid}</p>
              <p><strong>College Balance:</strong> {receiptData.collegeBalance}</p>
              <p><strong>Hostel Balance:</strong> {receiptData.hostelBalance}</p>
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
    </div>
  );
}
