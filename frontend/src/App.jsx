import { useEffect, useState, useCallback } from "react";
import { branches, colleges as collegesMaster, normalizeCollegeCode } from "./data/collegeData";

/* ─── API helpers ──────────────────────────────────────────────── */
const resolveApiBase = () => {
  const envUrl = String(import.meta.env.VITE_API_URL || "").trim();
  if (import.meta.env.DEV) return envUrl || "http://localhost:5000";
  if (envUrl && !/localhost|127\.0\.0\.1/i.test(envUrl)) return envUrl;
  return window.location.origin;
};
const API_BASE = resolveApiBase();
const TOKEN_KEY = "billing_token";

const HOSTEL_MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const nowDate = new Date();
const defaultHostelMonth = `${HOSTEL_MONTHS[nowDate.getMonth()]}-${nowDate.getFullYear()}`;

const hostelYearOptions = (() => {
  const y = nowDate.getFullYear();
  return Array.from({ length: 9 }, (_, i) => String(y - 1 + i));
})();

const parseMonthYear = (v) => {
  const m = String(v || "").match(/^([A-Za-z]{3})-(\d{4})$/);
  return m ? { month: m[1], year: m[2] } : { month: "", year: "" };
};

/* ─── Initial form states ──────────────────────────────────────── */
const init = {
  student: { pin:"", name:"", course:"", phone:"", collegeTotalFee:"", hasHostel:false },
  combinedPayment: { pin:"", phone:"", collegeAmountPaid:"", hostelAmountPaid:"", hostelMonth:"", hostelMonthName:"", hostelYear:"" },
  hostelFee: { month: defaultHostelMonth, monthlyFee:"" },
  attendance: { pin:"", month:"", totalDays:"", daysStayed:"" },
  login: { email:"", password:"" },
  createUser: { collegeKey:"default", email:"", name:"", role:"staff", password:"", active:"true" },
  adminStudent: { collegeKey:"", pin:"", name:"", course:"", phone:"", collegeTotalFee:"" },
  pwForm: { newPassword:"", confirmPassword:"" },
};

/* ─── Nav items ────────────────────────────────────────────────── */
const NAV_BILLING = [
  { id:"dashboard",  icon:"⬡",  label:"Dashboard" },
  { id:"students",   icon:"◈",  label:"Students" },
  { id:"payments",   icon:"◉",  label:"Payments" },
  { id:"hostel",     icon:"⬘",  label:"Hostel" },
  { id:"reports",    icon:"◫",  label:"Reports" },
];
const NAV_ADMIN = [
  { id:"admin-users",     icon:"◈", label:"Users" },
  { id:"admin-colleges",  icon:"⬡", label:"Colleges" },
  { id:"admin-students",  icon:"⬘", label:"Students" },
  { id:"admin-imports",   icon:"◫", label:"Imports" },
];

export default function App() {
  /* ── auth ─────────────────────────────────────────────────────── */
  const [token, setToken]   = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [me,    setMe]      = useState(null);
  const [loginForm, setLoginForm]   = useState(init.login);
  const [pwForm,    setPwForm]      = useState(init.pwForm);

  /* ── ui state ─────────────────────────────────────────────────── */
  const [page,    setPage]   = useState("dashboard");
  const [msg,     setMsg]    = useState({ text:"", kind:"" });
  const [sidebar, setSidebar]= useState(true);

  /* ── data ─────────────────────────────────────────────────────── */
  const [students,  setStudents]  = useState([]);
  const [dashboard, setDashboard] = useState([]);
  const [users,     setUsers]     = useState([]);
  const [colleges,  setColleges]  = useState([]);
  const [adminStudentImports, setAdminStudentImports] = useState([]);
  const [myStudentImports,    setMyStudentImports]    = useState([]);
  const [selectedImport,      setSelectedImport]      = useState(null);

  /* ── forms ─────────────────────────────────────────────────────── */
  const [studentForm,       setStudentForm]       = useState(init.student);
  const [combinedPaymentForm, setCombinedPaymentForm] = useState(init.combinedPayment);
  const [hostelFeeForm,     setHostelFeeForm]     = useState(init.hostelFee);
  const [attendanceForm,    setAttendanceForm]    = useState(init.attendance);
  const [createUserForm,    setCreateUserForm]    = useState(init.createUser);
  const [adminStudentForm,  setAdminStudentForm]  = useState(init.adminStudent);

  /* ── receipt/payment ──────────────────────────────────────────── */
  const [receiptPin,  setReceiptPin]   = useState("");
  const [receiptData, setReceiptData]  = useState(null);
  const [receiptPhone,setReceiptPhone] = useState("");
  const [receiptLoading,setReceiptLoading] = useState(false);
  const [lastPaymentReceipt, setLastPaymentReceipt] = useState(null);
  const [pinSearch,   setPinSearch]    = useState("");
  const [studentHostelFlag, setStudentHostelFlag] = useState(false);
  const [bulkDeletePins, setBulkDeletePins] = useState("");

  /* ── file inputs ──────────────────────────────────────────────── */
  const [importFile,            setImportFile]            = useState(null);
  const [studentImportFile,     setStudentImportFile]     = useState(null);
  const [adminStudentImportCollege, setAdminStudentImportCollege] = useState("");

  const isAdmin     = me?.role === "admin";
  const isPrincipal = me?.role === "principal";
  const BILLING_ROLES = ["admin","principal","accountant","staff"];

  const collegeDisplay = (() => {
    const code = normalizeCollegeCode(me?.collegeKey || "default");
    if (code === "default") return { code, name:"Default College" };
    const f = collegesMaster.find(c => c.code === code);
    return { code, name: f ? f.name : "Unknown College" };
  })();

  /* ── helpers ──────────────────────────────────────────────────── */
  const flash = (text, kind="success") => {
    setMsg({ text, kind });
    setTimeout(() => setMsg({ text:"", kind:"" }), 5000);
  };

  const readBody = async (res) => {
    const ct = String(res.headers.get("content-type")||"").toLowerCase();
    if (ct.includes("application/json")) {
      try { return { kind:"json", value: await res.json() }; } catch { return { kind:"json", value:null }; }
    }
    let text = ""; try { text = await res.text(); } catch {}
    return { kind:"text", value:text };
  };

  const errFrom = (res, body) => {
    if (body?.kind==="json" && body.value?.message) return body.value.message;
    if (body?.kind==="text") {
      const t = String(body.value||"");
      if (/<!doctype/i.test(t)||/<html/i.test(t)) return "API URL mismatch (got HTML). Check VITE_API_URL.";
      return (t.split(/\n/)[0]||"").slice(0,160) || `HTTP ${res.status}`;
    }
    return `Request failed (HTTP ${res.status})`;
  };

  const callApi = useCallback(async (path, method="GET", body=null) => {
    const headers = {};
    if (body!==null) headers["Content-Type"]="application/json";
    if (token) headers.Authorization=`Bearer ${token}`;
    const res = await fetch(`${API_BASE}${path}`, { method, headers, body: body!==null?JSON.stringify(body):undefined });
    const parsed = await readBody(res);
    if (!res.ok) throw new Error(errFrom(res,parsed));
    if (parsed.kind!=="json") throw new Error("Server returned non-JSON");
    return parsed.value;
  }, [token]);

  const uploadFile = useCallback(async (path, file, fields={}) => {
    const headers = {};
    if (token) headers.Authorization=`Bearer ${token}`;
    const fd = new FormData();
    fd.append("file", file);
    Object.entries(fields).forEach(([k,v]) => fd.append(k, String(v??"")));
    const res = await fetch(`${API_BASE}${path}`, { method:"POST", headers, body:fd });
    const parsed = await readBody(res);
    if (!res.ok) throw new Error(errFrom(res,parsed));
    if (parsed.kind!=="json") throw new Error("Server returned non-JSON");
    return parsed.value;
  }, [token]);

  const handleInput = setter => e =>
    setter(p => ({ ...p, [e.target.name]: e.target.value }));

  const setMonthYear = (setter, field, part, val) =>
    setter(p => {
      const cur = parseMonthYear(p[field]);
      const mo = part==="month" ? val : cur.month;
      const yr = part==="year"  ? val : cur.year;
      return { ...p, [field]: mo&&yr ? `${mo}-${yr}` : "" };
    });

  /* ── data loaders ─────────────────────────────────────────────── */
  const loadDashboard = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([callApi("/api/students"), callApi("/api/dashboard/students")]);
      setStudents(s); setDashboard(d);
    } catch(e) { flash(e.message,"error"); }
  }, [callApi]);

  const loadUsers = useCallback(async () => {
    if (!isAdmin) return;
    try { setUsers(await callApi("/api/admin/users")); }
    catch(e) { flash(e.message,"error"); }
  }, [callApi, isAdmin]);

  const loadColleges = useCallback(async () => {
    if (!isAdmin) return;
    try { setColleges(await callApi("/api/admin/colleges")); }
    catch(e) { flash(e.message,"error"); }
  }, [callApi, isAdmin]);

  const loadMyImports = useCallback(async () => {
    if (!isPrincipal) return;
    try { setMyStudentImports(await callApi("/api/student-imports/my")); }
    catch(e) { flash(e.message,"error"); }
  }, [callApi, isPrincipal]);

  const loadAdminImports = useCallback(async () => {
    if (!isAdmin) return;
    try { setAdminStudentImports(await callApi("/api/admin/student-imports")); }
    catch(e) { flash(e.message,"error"); }
  }, [callApi, isAdmin]);

  const loadMe = async (tok) => {
    try {
      const headers = tok ? { Authorization:`Bearer ${tok}` } : {};
      const res = await fetch(`${API_BASE}/api/auth/me`, { headers });
      const p = await readBody(res);
      if (!res.ok) throw new Error(errFrom(res,p));
      setMe(p.value.user);
    } catch { setMe(null); setToken(""); localStorage.removeItem(TOKEN_KEY); }
  };

  useEffect(() => { if (token) loadMe(token); }, [token]);

  useEffect(() => {
    if (!me || me.mustChangePassword) return;
    loadDashboard();
    if (isAdmin) { loadUsers(); loadColleges(); loadAdminImports(); }
    if (isPrincipal) loadMyImports();
  }, [me?.id]);

  /* ── receipt auto-load ────────────────────────────────────────── */
  const loadReceipt = useCallback(async (pin) => {
    if (!pin) { setReceiptData(null); return; }
    setReceiptLoading(true);
    try {
      const d = await callApi(`/api/receipt/${encodeURIComponent(pin)}`);
      setReceiptData(d); setReceiptPhone(d.phone||"");
    } catch(e) { flash(e.message,"error"); setReceiptData(null); }
    finally { setReceiptLoading(false); }
  }, [callApi]);

  useEffect(() => {
    const pin = receiptPin.trim();
    if (!pin) { setReceiptData(null); return; }
    const t = setTimeout(() => loadReceipt(pin), 380);
    return () => clearTimeout(t);
  }, [receiptPin]);

  useEffect(() => {
    if (receiptData?.pin) {
      setCombinedPaymentForm(p => ({ ...p, pin: receiptData.pin }));
      setAttendanceForm(p => ({ ...p, pin: receiptData.pin }));
    }
  }, [receiptData?.pin]);

  useEffect(() => {
    setCombinedPaymentForm(p => {
      const m = p.hostelMonthName, y = p.hostelYear;
      const month = m && y ? `${m}-${y}` : "";
      return p.hostelMonth===month ? p : { ...p, hostelMonth:month };
    });
  }, [combinedPaymentForm.hostelMonthName, combinedPaymentForm.hostelYear]);

  useEffect(() => { setStudentHostelFlag(!!receiptData?.hasHostel); }, [receiptData?.pin]);

  /* ── auth actions ─────────────────────────────────────────────── */
  const login = async (e) => {
    e.preventDefault();
    try {
      const d = await callApi("/api/auth/login","POST",loginForm);
      localStorage.setItem(TOKEN_KEY,d.token); setToken(d.token); setMe(d.user);
      setLoginForm(init.login);
    } catch(e2) { flash(e2.message,"error"); }
  };

  const logout = () => {
    setMe(null); setToken(""); localStorage.removeItem(TOKEN_KEY);
    setStudents([]); setDashboard([]); setReceiptData(null); setReceiptPin("");
  };

  const changePassword = async (e) => {
    e.preventDefault();
    if (pwForm.newPassword.length < 8) return flash("Min 8 characters","error");
    if (pwForm.newPassword !== pwForm.confirmPassword) return flash("Passwords don't match","error");
    try {
      const d = await callApi("/api/auth/change-password","POST",{ newPassword:pwForm.newPassword });
      localStorage.setItem(TOKEN_KEY,d.token); setToken(d.token); setMe(d.user);
      setPwForm(init.pwForm); flash("Password updated!");
    } catch(e) { flash(e.message,"error"); }
  };

  /* ── student actions ──────────────────────────────────────────── */
  const submitStudent = async (e) => {
    e.preventDefault();
    try {
      await callApi("/api/student-submissions","POST",{
        pin:studentForm.pin.trim(), name:studentForm.name.trim(),
        course:studentForm.course.trim(), phone:studentForm.phone.trim(),
        collegeTotalFee:Number(studentForm.collegeTotalFee||0),
        hasHostel:!!studentForm.hasHostel
      });
      flash("Student submitted to admin for approval");
      setStudentForm(init.student);
      loadMyImports();
    } catch(e) { flash(e.message,"error"); }
  };

  const deleteSingleStudent = async (pin) => {
    if (!window.confirm(`Delete student ${pin}? This will also delete their payment records.`)) return;
    try {
      await callApi(`/api/students/${encodeURIComponent(pin)}`,"DELETE");
      if (receiptPin.trim()===pin) { setReceiptPin(""); setReceiptData(null); }
      await loadDashboard(); flash(`Deleted student ${pin}`);
    } catch(e) { flash(e.message,"error"); }
  };

  const deleteBulkStudents = async () => {
    const pins = bulkDeletePins.split(/[\s,]+/).map(p=>p.trim()).filter(Boolean);
    if (!pins.length) return flash("Enter at least one PIN","error");
    if (!window.confirm(`Delete ${pins.length} students?`)) return;
    try {
      await callApi("/api/students/delete","POST",{ pins });
      setBulkDeletePins(""); await loadDashboard(); flash(`Deleted ${pins.length} students`);
    } catch(e) { flash(e.message,"error"); }
  };

  /* ── payment actions ──────────────────────────────────────────── */
  const savePayment = async (e) => {
    e.preventDefault();
    try {
      const r = await callApi("/api/payments","POST",combinedPaymentForm);
      if (r?.receiptNo) setLastPaymentReceipt({ receiptNo:r.receiptNo, receiptKey:r.receiptKey||"" });
      flash("Payment saved & receipt generated");
      setCombinedPaymentForm(p => ({ ...init.combinedPayment, pin:p.pin }));
      await loadDashboard();
      if (receiptPin.trim()) await loadReceipt(receiptPin.trim());
    } catch(e) { flash(e.message,"error"); }
  };

  const saveHostelFee = async (e) => {
    e.preventDefault();
    try {
      await callApi("/api/hostel-fees","POST",hostelFeeForm);
      flash("Hostel fee saved"); setHostelFeeForm(init.hostelFee);
    } catch(e) { flash(e.message,"error"); }
  };

  const saveAttendance = async (e) => {
    e.preventDefault();
    try {
      await callApi("/api/hostel-attendance","POST",attendanceForm);
      flash("Attendance saved");
      setAttendanceForm(p => ({ ...init.attendance, pin:p.pin }));
      if (receiptPin.trim()) await loadReceipt(receiptPin.trim());
      await loadDashboard();
    } catch(e) { flash(e.message,"error"); }
  };

  const updateHostelStatus = async () => {
    try {
      await callApi(`/api/students/${encodeURIComponent(receiptData.pin)}/hostel`,"PATCH",{ hasHostel:studentHostelFlag });
      flash("Hostel status updated"); await loadReceipt(receiptData.pin); await loadDashboard();
    } catch(e) { flash(e.message,"error"); }
  };

  /* ── pdf/csv downloads ────────────────────────────────────────── */
  const downloadPdf = async (url, filename) => {
    try {
      const headers = token ? { Authorization:`Bearer ${token}` } : {};
      const res = await fetch(`${API_BASE}${url}`, { headers });
      if (!res.ok) throw new Error((await res.json().catch(()=>({}))).message||"Failed");
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = filename;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
      flash("PDF downloaded");
    } catch(e) { flash(e.message,"error"); }
  };

  const downloadCsv = (rows, filename) => {
    if (!rows?.length) return flash("No data to export","error");
    const h = ["PIN","Name","Course","College Total","College Paid","College Balance","Hostel Charged","Hostel Paid","Hostel Balance","Total Balance"];
    const esc = v => { const s=String(v??""); return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; };
    const lines = rows.map(r=>[r.pin,r.name,r.course,r.collegeTotalFee,r.collegePaid,r.collegeBalance,r.hostelCharged,r.hostelPaid,r.hostelBalance,Number(r.collegeBalance||0)+Number(r.hostelBalance||0)].map(esc).join(","));
    const blob = new Blob([[h.join(","),...lines].join("\n")], { type:"text/csv;charset=utf-8;" });
    const a = document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=filename;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  };

  /* ── admin actions ────────────────────────────────────────────── */
  const saveUser = async (e) => {
    e.preventDefault();
    try {
      const r = await callApi("/api/admin/users","POST",{ ...createUserForm, active:createUserForm.active!=="false" });
      flash(`User saved.${r.temporaryPassword?` Temp password: ${r.temporaryPassword}`:""}`);
      setCreateUserForm(init.createUser); await Promise.all([loadUsers(),loadColleges()]);
    } catch(e) { flash(e.message,"error"); }
  };

  const importUsers = async (e) => {
    e.preventDefault();
    if (!importFile) return flash("Select a file","error");
    try {
      const r = await uploadFile("/api/admin/users/import", importFile);
      flash(`Imported: ${r.created} created, ${r.updated} updated`);
      if (r.errors?.length) flash(`Row errors: ${r.errors[0].row}: ${r.errors[0].message}`,"error");
      setImportFile(null); await Promise.all([loadUsers(),loadColleges()]);
    } catch(e) { flash(e.message,"error"); }
  };

  const resetPassword = async (id) => {
    try {
      const r = await callApi(`/api/admin/users/${id}/reset-password`,"POST",{});
      flash(`Password reset.${r.temporaryPassword?` Temp: ${r.temporaryPassword}`:""}`);
      await loadUsers();
    } catch(e) { flash(e.message,"error"); }
  };

  const saveAdminStudent = async (e) => {
    e.preventDefault();
    try {
      await callApi("/api/students","POST",adminStudentForm);
      flash("Student saved"); setAdminStudentForm(init.adminStudent);
    } catch(e) { flash(e.message,"error"); }
  };

  const submitStudentImport = async (e) => {
    e.preventDefault();
    if (!studentImportFile) return flash("Select a file","error");
    try {
      const r = isAdmin
        ? await uploadFile("/api/student-imports", studentImportFile, { collegeKey:adminStudentImportCollege })
        : await uploadFile("/api/student-imports", studentImportFile);
      flash(isAdmin
        ? `Import complete: created=${r.result?.created??0} updated=${r.result?.updated??0}`
        : `Submitted: ${r.rows} rows, status=${r.status}`);
      setStudentImportFile(null);
      await Promise.all([loadMyImports(), loadAdminImports()]);
    } catch(e) { flash(e.message,"error"); }
  };

  const approveImport = async (id) => {
    try {
      const r = await callApi(`/api/admin/student-imports/${id}/approve`,"POST",{});
      flash(`Approved: created=${r.result?.created??0} updated=${r.result?.updated??0}`);
      setSelectedImport(null); await loadAdminImports();
    } catch(e) { flash(e.message,"error"); }
  };

  const rejectImport = async (id) => {
    try {
      await callApi(`/api/admin/student-imports/${id}/reject`,"POST",{});
      flash("Import rejected"); setSelectedImport(null); await loadAdminImports();
    } catch(e) { flash(e.message,"error"); }
  };

  const setCollegeActive = async (key, active) => {
    try {
      await callApi("/api/admin/colleges/active","POST",{ collegeKey:key, active });
      flash(`College ${key} ${active?"enabled":"disabled"}`); await loadColleges();
    } catch(e) { flash(e.message,"error"); }
  };

  const downloadTemplate = async (url, filename) => {
    try {
      const headers = token ? { Authorization:`Bearer ${token}` } : {};
      const res = await fetch(`${API_BASE}${url}`,{ headers });
      const blob = await res.blob();
      const a = document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=filename;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
    } catch(e) { flash(e.message,"error"); }
  };

  /* ── derived ──────────────────────────────────────────────────── */
  const balanceRows = dashboard.map(r=>({ ...r, totalBalance:Number(r.collegeBalance||0)+Number(r.hostelBalance||0) }));
  const withBalance = balanceRows.filter(r=>r.totalBalance>0).sort((a,b)=>b.totalBalance-a.totalBalance);
  const cleared     = balanceRows.filter(r=>r.totalBalance<=0).sort((a,b)=>String(a.pin).localeCompare(String(b.pin)));
  const hostelStudents = students.filter(s=>s.hasHostel).sort((a,b)=>String(a.pin).localeCompare(String(b.pin)));
  const showHostel = !!receiptData && (receiptData.hasHostel||Number(receiptData.hostelCharged||0)>0||Number(receiptData.hostelPaid||0)>0);

  /* ══════════════════════════════════════════════════════════════
     LOGIN SCREEN
  ══════════════════════════════════════════════════════════════ */
  if (!me) return (
    <div className="auth-shell">
      <div className="auth-left">
        <div className="auth-brand">
          <span className="auth-logo">⬡</span>
          <h1>BillingOS</h1>
          <p>College Fee &amp; Hostel Management</p>
        </div>
        <ul className="auth-features">
          <li><span>◈</span> Student master &amp; fee tracking</li>
          <li><span>◉</span> College &amp; hostel payments</li>
          <li><span>◫</span> PDF receipts &amp; balance reports</li>
          <li><span>⬘</span> Multi-college &amp; role-based access</li>
        </ul>
      </div>
      <div className="auth-right">
        <div className="auth-card">
          <h2>Sign in</h2>
          {msg.text && <div className={`toast ${msg.kind}`}>{msg.text}</div>}
          <form onSubmit={login}>
            <label>Email address</label>
            <input name="email" type="email" placeholder="admin@example.com"
              value={loginForm.email} onChange={handleInput(setLoginForm)} required />
            <label>Password</label>
            <input name="password" type="password" placeholder="••••••••"
              value={loginForm.password} onChange={handleInput(setLoginForm)} required />
            <button type="submit" className="btn-primary full">Sign In</button>
          </form>
        </div>
      </div>
    </div>
  );

  /* ══════════════════════════════════════════════════════════════
     CHANGE PASSWORD SCREEN
  ══════════════════════════════════════════════════════════════ */
  if (me.mustChangePassword) return (
    <div className="auth-shell">
      <div className="auth-right" style={{flex:1}}>
        <div className="auth-card">
          <h2>Set your password</h2>
          <p style={{color:"var(--text-muted)",marginBottom:16}}>You must set a new password before continuing.</p>
          {msg.text && <div className={`toast ${msg.kind}`}>{msg.text}</div>}
          <form onSubmit={changePassword}>
            <label>New password (min 8 chars)</label>
            <input type="password" placeholder="New password"
              value={pwForm.newPassword} onChange={e=>setPwForm(p=>({...p,newPassword:e.target.value}))} required />
            <label>Confirm password</label>
            <input type="password" placeholder="Confirm password"
              value={pwForm.confirmPassword} onChange={e=>setPwForm(p=>({...p,confirmPassword:e.target.value}))} required />
            <button type="submit" className="btn-primary full">Save Password</button>
          </form>
          <button className="btn-ghost" style={{marginTop:8}} onClick={logout}>Logout</button>
        </div>
      </div>
    </div>
  );

  /* ══════════════════════════════════════════════════════════════
     MAIN APP SHELL
  ══════════════════════════════════════════════════════════════ */
  const nav = isAdmin ? NAV_ADMIN : NAV_BILLING;
  const defaultPage = isAdmin ? "admin-users" : "dashboard";
  const activePage = nav.find(n=>n.id===page) ? page : defaultPage;

  return (
    <div className={`app-shell ${sidebar?"sidebar-open":"sidebar-closed"}`}>
      {/* ── datalists ── */}
      <datalist id="collegeOpts">
        <option value="default">default</option>
        {collegesMaster.map(c=><option key={c.code} value={c.code}>{c.code} – {c.name}</option>)}
      </datalist>
      <datalist id="courseOpts">
        {branches.map(b=><option key={b} value={b}/>)}
      </datalist>

      {/* ── SIDEBAR ── */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-logo">⬡</span>
          {sidebar && <span className="sidebar-title">BillingOS</span>}
          <button className="sidebar-toggle" onClick={()=>setSidebar(s=>!s)}>{sidebar?"←":"→"}</button>
        </div>
        <nav className="sidebar-nav">
          {nav.map(n=>(
            <button key={n.id}
              className={`nav-item ${activePage===n.id?"active":""}`}
              onClick={()=>setPage(n.id)}
              title={n.label}
            >
              <span className="nav-icon">{n.icon}</span>
              {sidebar && <span className="nav-label">{n.label}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <span className="user-avatar">{(me.name||"U")[0].toUpperCase()}</span>
            {sidebar && (
              <div className="user-info">
                <span className="user-name">{me.name}</span>
                <span className="user-role">{me.role}{!isAdmin && ` · ${collegeDisplay.code}`}</span>
              </div>
            )}
          </div>
          {sidebar && <button className="btn-logout" onClick={logout}>Logout</button>}
        </div>
      </aside>

      {/* ── MAIN ── */}
      <main className="main-content">
        {/* Toast */}
        {msg.text && <div className={`toast ${msg.kind}`}>{msg.text}</div>}

        {/* ━━━━━━━━━━━━━━━━━━━━━━━━━ BILLING PAGES ━━━━━━━━━━━━━━━━━━━━━━━━━ */}

        {/* DASHBOARD */}
        {!isAdmin && activePage==="dashboard" && (
          <PageShell title="Dashboard" subtitle="Overview of your college fee & hostel billing">
            <div className="stats-grid">
              <StatCard icon="◈" label="Total Students" value={students.length} color="blue"/>
              <StatCard icon="⚠" label="With Balance Due" value={withBalance.length} color="red"/>
              <StatCard icon="✓" label="Fully Cleared" value={cleared.length} color="green"/>
              <StatCard icon="⬘" label="Hostel Students" value={hostelStudents.length} color="purple"/>
            </div>
            <div className="section-grid">
              <section className="card">
                <h3 className="card-title">Top 10 Outstanding Balances</h3>
                {withBalance.length===0 ? <Empty text="All students cleared!"/> : (
                  <Table cols={["PIN","Name","College Bal","Hostel Bal","Total"]}
                    rows={withBalance.slice(0,10).map(r=>[
                      <button className="link-btn" onClick={()=>{setPage("payments");setReceiptPin(r.pin);}}>{r.pin}</button>,
                      r.name, r.collegeBalance, r.hostelBalance,
                      <strong style={{color:"var(--red)"}}>{r.totalBalance}</strong>
                    ])}/>
                )}
              </section>
              <section className="card">
                <h3 className="card-title">Quick Actions</h3>
                <div className="quick-actions">
                  <QuickAction icon="◉" label="Record Payment" onClick={()=>setPage("payments")}/>
                  <QuickAction icon="◈" label="Add Student" onClick={()=>setPage("students")}/>
                  <QuickAction icon="⬘" label="Hostel Fee Master" onClick={()=>setPage("hostel")}/>
                  <QuickAction icon="◫" label="View Reports" onClick={()=>setPage("reports")}/>
                </div>
              </section>
            </div>
          </PageShell>
        )}

        {/* STUDENTS */}
        {!isAdmin && activePage==="students" && (
          <PageShell title="Students" subtitle="Manage student records">
            <div className="tab-pills">
              {isPrincipal && <>[
                <TabPill id="s-add" label="Add Student" />,
                <TabPill id="s-import" label="Bulk Import" />,
                <TabPill id="s-history" label="Import History" />,
              ]</>}
              <TabPill id="s-list" label="All Students" default/>
              <TabPill id="s-delete" label="Delete Students" />
            </div>
            <SubTabView>
              {isPrincipal && (
                <SubTab id="s-add">
                  <section className="card">
                    <h3 className="card-title">Submit New Student to Admin</h3>
                    <form onSubmit={submitStudent} className="form-grid">
                      <Field label="PIN / Roll Number">
                        <input name="pin" placeholder="220001" value={studentForm.pin} onChange={handleInput(setStudentForm)} required/>
                      </Field>
                      <Field label="Student Name">
                        <input name="name" placeholder="Full name" value={studentForm.name} onChange={handleInput(setStudentForm)} required/>
                      </Field>
                      <Field label="Course / Branch">
                        <input name="course" list="courseOpts" placeholder="COMPUTER ENGINEERING" value={studentForm.course} onChange={handleInput(setStudentForm)} required/>
                      </Field>
                      <Field label="Phone (optional)">
                        <input name="phone" placeholder="9876543210" value={studentForm.phone} onChange={handleInput(setStudentForm)}/>
                      </Field>
                      <Field label="College Total Fee (₹)">
                        <input name="collegeTotalFee" type="number" min="0" placeholder="12000" value={studentForm.collegeTotalFee} onChange={handleInput(setStudentForm)} required/>
                      </Field>
                      <Field label="Hostel Student?">
                        <label className="toggle-label">
                          <input type="checkbox" checked={!!studentForm.hasHostel} onChange={e=>setStudentForm(p=>({...p,hasHostel:e.target.checked}))}/>
                          <span>{studentForm.hasHostel?"Yes – has hostel":"No hostel"}</span>
                        </label>
                      </Field>
                      <div className="form-actions">
                        <button type="submit" className="btn-primary">Submit to Admin</button>
                      </div>
                    </form>
                    <p className="hint">Admin will review and approve. Students will appear after approval.</p>
                  </section>
                </SubTab>
              )}
              {isPrincipal && (
                <SubTab id="s-import">
                  <section className="card">
                    <h3 className="card-title">Bulk Import Students (Excel / CSV)</h3>
                    <div className="action-bar">
                      <button className="btn-secondary" onClick={()=>downloadTemplate("/api/student-imports/template","students_template.csv")}>
                        ↓ Download Template
                      </button>
                    </div>
                    <form onSubmit={submitStudentImport} className="form-grid">
                      <Field label="Select File (.xlsx or .csv)">
                        <input type="file" accept=".xlsx,.xls,.csv" onChange={e=>setStudentImportFile(e.target.files?.[0]||null)} required/>
                      </Field>
                      <div className="form-actions">
                        <button type="submit" className="btn-primary">Upload &amp; Submit to Admin</button>
                      </div>
                    </form>
                    <p className="hint">Columns required: pin, name, course, phone, hasHostel, collegeTotalFee</p>
                  </section>
                </SubTab>
              )}
              {isPrincipal && (
                <SubTab id="s-history">
                  <section className="card">
                    <h3 className="card-title">My Import History</h3>
                    {myStudentImports.length===0 ? <Empty text="No imports yet"/> : (
                      <Table cols={["Date","File","Rows","Status","Note"]}
                        rows={myStudentImports.map(r=>[
                          new Date(r.createdAt).toLocaleString(),
                          r.originalName,
                          r.rowsCount||"-",
                          <StatusPill status={r.status}/>,
                          r.decisionNote||"-"
                        ])}/>
                    )}
                  </section>
                </SubTab>
              )}
              <SubTab id="s-list" default>
                <section className="card">
                  <h3 className="card-title">All Students ({students.length})</h3>
                  {students.length===0 ? <Empty text="No students yet"/> : (
                    <Table cols={["PIN","Name","Course","Phone","Hostel","College Fee",isPrincipal?"Action":""]}
                      rows={students.map(s=>[
                        s.pin, s.name, s.course, s.phone||"-",
                        s.hasHostel ? <span className="pill green">Yes</span> : <span className="pill">No</span>,
                        `₹${s.collegeTotalFee}`,
                        isPrincipal ? <button className="btn-danger-sm" onClick={()=>deleteSingleStudent(s.pin)}>Delete</button> : ""
                      ])}/>
                  )}
                </section>
              </SubTab>
              <SubTab id="s-delete">
                <section className="card">
                  <h3 className="card-title">Delete Students</h3>
                  <p className="hint" style={{marginBottom:12}}>⚠ This permanently removes students and their payment history.</p>
                  <Field label="Enter PINs (comma, space or newline separated)">
                    <textarea rows={5} placeholder="220001, 220002&#10;220003"
                      value={bulkDeletePins} onChange={e=>setBulkDeletePins(e.target.value)}/>
                  </Field>
                  <div className="form-actions">
                    <button className="btn-danger" onClick={deleteBulkStudents}>Delete Students</button>
                  </div>
                  <h3 className="card-title" style={{marginTop:20}}>Delete Individual Student</h3>
                  {students.length===0 ? <Empty text="No students"/> : (
                    <Table cols={["PIN","Name","Action"]}
                      rows={students.map(s=>[
                        s.pin, s.name,
                        <button className="btn-danger-sm" onClick={()=>deleteSingleStudent(s.pin)}>Delete</button>
                      ])}/>
                  )}
                </section>
              </SubTab>
            </SubTabView>
          </PageShell>
        )}

        {/* PAYMENTS */}
        {!isAdmin && activePage==="payments" && (
          <PageShell title="Payments" subtitle="Record college & hostel fee payments">
            <div className="payment-layout">
              {/* LEFT: lookup */}
              <section className="card payment-lookup">
                <h3 className="card-title">Student Lookup</h3>
                <div className="search-row">
                  <input value={receiptPin} onChange={e=>setReceiptPin(e.target.value)}
                    placeholder="Type PIN / Roll No…" className="search-input"/>
                  {receiptPin && <button className="btn-ghost" onClick={()=>{setReceiptPin("");setReceiptData(null);setLastPaymentReceipt(null);}}>✕</button>}
                </div>
                {receiptLoading && <div className="loading-bar"/>}
                {receiptData && (
                  <div className="receipt-card">
                    <div className="receipt-name">{receiptData.name}</div>
                    <div className="receipt-sub">{receiptData.pin} · {receiptData.course}</div>
                    <div className="receipt-grid">
                      <ReceiptRow label="Phone" value={receiptData.phone||"-"}/>
                      <ReceiptRow label="College Total" value={`₹${receiptData.collegeTotalFee}`}/>
                      <ReceiptRow label="College Paid" value={`₹${receiptData.collegePaid}`}/>
                      <ReceiptRow label="College Balance" value={`₹${receiptData.collegeBalance}`} highlight={receiptData.collegeBalance>0}/>
                      {showHostel && <>
                        <ReceiptRow label="Hostel Charged" value={`₹${receiptData.hostelCharged}`}/>
                        <ReceiptRow label="Hostel Paid"    value={`₹${receiptData.hostelPaid}`}/>
                        <ReceiptRow label="Hostel Balance" value={`₹${receiptData.hostelBalance}`} highlight={receiptData.hostelBalance>0}/>
                      </>}
                      {!showHostel && <ReceiptRow label="Hostel" value="College-only student"/>}
                    </div>
                    {isPrincipal && (
                      <div className="hostel-toggle">
                        <label className="toggle-label">
                          <input type="checkbox" checked={studentHostelFlag} onChange={e=>setStudentHostelFlag(e.target.checked)}/>
                          <span>Hostel student</span>
                        </label>
                        <button className="btn-secondary sm" onClick={updateHostelStatus}>Update</button>
                      </div>
                    )}
                    <div className="receipt-actions">
                      <button className="btn-secondary sm" onClick={()=>downloadPdf(`/api/receipt/${receiptPin}/pdf`,`receipt_${receiptPin}.pdf`)}>
                        ↓ Balance PDF
                      </button>
                      {lastPaymentReceipt?.receiptNo && (
                        <button className="btn-secondary sm" onClick={()=>downloadPdf(`/api/payment-receipts/${lastPaymentReceipt.receiptNo}/pdf`,`payment_receipt_${lastPaymentReceipt.receiptNo}.pdf`)}>
                          ↓ Payment Receipt PDF
                        </button>
                      )}
                      {["principal","admin"].includes(me?.role) && (
                        <button className="btn-secondary sm" onClick={()=>{
                          const raw=receiptPhone.replace(/\D/g,"");
                          if(!raw) return flash("Enter phone number","error");
                          const total=Number(receiptData.collegeBalance||0)+Number(receiptData.hostelBalance||0);
                          const text = total>0
                            ? `Hello ${receiptData.name}, your fee balance: College ₹${receiptData.collegeBalance}, Hostel ₹${receiptData.hostelBalance}. Total due ₹${total}.`
                            : `Hello ${receiptData.name}, your fees are cleared. College paid ₹${receiptData.collegePaid}.`;
                          window.open(`https://wa.me/${raw}?text=${encodeURIComponent(text)}`,"_blank","noopener");
                        }}>WhatsApp</button>
                      )}
                    </div>
                    {lastPaymentReceipt?.receiptNo && (
                      <p className="hint" style={{marginTop:6}}>
                        Last receipt: <b>{lastPaymentReceipt.receiptNo}</b>{lastPaymentReceipt.receiptKey&&` · Key: ${lastPaymentReceipt.receiptKey}`}
                      </p>
                    )}
                  </div>
                )}
                {!receiptData && !receiptLoading && (
                  <p className="hint" style={{marginTop:12}}>Search by PIN to view student details and record payments.</p>
                )}
              </section>

              {/* RIGHT: payment form */}
              <section className="card">
                <h3 className="card-title">Record Payment</h3>
                {!receiptData ? (
                  <div className="empty-state small">
                    <p>Search for a student first →</p>
                  </div>
                ) : (
                  <form onSubmit={savePayment} className="form-grid">
                    <Field label="Student PIN">
                      <input value={combinedPaymentForm.pin} readOnly className="input-readonly"/>
                    </Field>
                    <Field label="Phone (optional)">
                      <input name="phone" placeholder="Contact number" value={combinedPaymentForm.phone} onChange={handleInput(setCombinedPaymentForm)}/>
                    </Field>
                    <Field label="College Amount Paid (₹)">
                      <input name="collegeAmountPaid" type="number" min="0" placeholder="0"
                        value={combinedPaymentForm.collegeAmountPaid} onChange={handleInput(setCombinedPaymentForm)}/>
                    </Field>
                    <Field label="Hostel Amount Paid (₹)">
                      <input name="hostelAmountPaid" type="number" min="0" placeholder="0"
                        value={combinedPaymentForm.hostelAmountPaid} onChange={handleInput(setCombinedPaymentForm)}
                        disabled={!showHostel}/>
                    </Field>
                    <Field label="Hostel Month">
                      <div className="two-col">
                        <select value={combinedPaymentForm.hostelMonthName} name="hostelMonthName"
                          onChange={handleInput(setCombinedPaymentForm)} disabled={!showHostel}>
                          <option value="">Month</option>
                          {HOSTEL_MONTHS.map(m=><option key={m} value={m}>{m}</option>)}
                        </select>
                        <select value={combinedPaymentForm.hostelYear} name="hostelYear"
                          onChange={handleInput(setCombinedPaymentForm)} disabled={!showHostel}>
                          <option value="">Year</option>
                          {hostelYearOptions.map(y=><option key={y} value={y}>{y}</option>)}
                        </select>
                      </div>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary full">
                        Save Payment &amp; Generate Receipt
                      </button>
                    </div>
                    {!showHostel && <p className="hint">Hostel fields disabled — not a hostel student.</p>}
                  </form>
                )}

                {/* Phone / WA override for receipt */}
                {receiptData && (
                  <div style={{marginTop:16}}>
                    <Field label="Override Phone for WhatsApp/Receipt">
                      <input value={receiptPhone} onChange={e=>setReceiptPhone(e.target.value)} placeholder="Phone number"/>
                    </Field>
                  </div>
                )}
              </section>
            </div>
          </PageShell>
        )}

        {/* HOSTEL */}
        {!isAdmin && activePage==="hostel" && (
          <PageShell title="Hostel" subtitle="Manage hostel fee master and student attendance">
            <div className="tab-pills">
              <TabPill id="h-fee" label="Fee Master" default/>
              <TabPill id="h-attendance" label="Attendance"/>
            </div>
            <SubTabView>
              <SubTab id="h-fee" default>
                <section className="card">
                  <h3 className="card-title">Hostel Fee Master</h3>
                  <p className="hint" style={{marginBottom:12}}>Set the monthly fee amount. This is used to calculate pro-rated attendance fees.</p>
                  <form onSubmit={saveHostelFee} className="form-grid">
                    <Field label="Month">
                      <div className="two-col">
                        <select value={parseMonthYear(hostelFeeForm.month).month}
                          onChange={e=>setMonthYear(setHostelFeeForm,"month","month",e.target.value)}>
                          <option value="">Select Month</option>
                          {HOSTEL_MONTHS.map(m=><option key={m} value={m}>{m}</option>)}
                        </select>
                        <select value={parseMonthYear(hostelFeeForm.month).year}
                          onChange={e=>setMonthYear(setHostelFeeForm,"month","year",e.target.value)}>
                          <option value="">Select Year</option>
                          {hostelYearOptions.map(y=><option key={y} value={y}>{y}</option>)}
                        </select>
                      </div>
                    </Field>
                    <Field label="Monthly Fee (₹)">
                      <input name="monthlyFee" type="number" min="0" placeholder="5000"
                        value={hostelFeeForm.monthlyFee} onChange={handleInput(setHostelFeeForm)} required/>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Save Fee</button>
                    </div>
                  </form>
                  <div className="info-box" style={{marginTop:16}}>
                    <b>Formula:</b> calculatedFee = round((monthlyFee ÷ totalDays) × daysStayed)
                  </div>
                </section>
              </SubTab>
              <SubTab id="h-attendance">
                <section className="card">
                  <h3 className="card-title">Record Hostel Attendance</h3>
                  <p className="hint" style={{marginBottom:12}}>Select a hostel student and enter their attendance for the month. Fee is auto-calculated.</p>
                  <form onSubmit={saveAttendance} className="form-grid">
                    <Field label="Student">
                      <select name="pin" value={attendanceForm.pin}
                        onChange={e=>{setAttendanceForm(p=>({...p,pin:e.target.value}));setReceiptPin(e.target.value);}} required>
                        <option value="">Select hostel student</option>
                        {hostelStudents.map(s=><option key={s._id} value={s.pin}>{s.pin} — {s.name}</option>)}
                      </select>
                    </Field>
                    <Field label="Month">
                      <div className="two-col">
                        <select value={parseMonthYear(attendanceForm.month).month}
                          onChange={e=>setMonthYear(setAttendanceForm,"month","month",e.target.value)}>
                          <option value="">Month</option>
                          {HOSTEL_MONTHS.map(m=><option key={m} value={m}>{m}</option>)}
                        </select>
                        <select value={parseMonthYear(attendanceForm.month).year}
                          onChange={e=>setMonthYear(setAttendanceForm,"month","year",e.target.value)}>
                          <option value="">Year</option>
                          {hostelYearOptions.map(y=><option key={y} value={y}>{y}</option>)}
                        </select>
                      </div>
                    </Field>
                    <Field label="Total Days in Month">
                      <input name="totalDays" type="number" min="1" max="31" placeholder="30"
                        value={attendanceForm.totalDays} onChange={handleInput(setAttendanceForm)} required/>
                    </Field>
                    <Field label="Days Stayed">
                      <input name="daysStayed" type="number" min="0" placeholder="28"
                        value={attendanceForm.daysStayed} onChange={handleInput(setAttendanceForm)} required/>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Save Attendance</button>
                    </div>
                  </form>
                  {hostelStudents.length===0 && (
                    <div className="info-box" style={{marginTop:12}}>
                      No hostel students found. Mark students as hostel in the Students section.
                    </div>
                  )}
                </section>
              </SubTab>
            </SubTabView>
          </PageShell>
        )}

        {/* REPORTS */}
        {!isAdmin && activePage==="reports" && (
          <PageShell title="Reports" subtitle="Balance reports and data exports">
            <div className="tab-pills">
              <TabPill id="r-due" label="Balance Due" default/>
              <TabPill id="r-cleared" label="Cleared Students"/>
              <TabPill id="r-all" label="All Students"/>
            </div>
            <SubTabView>
              <SubTab id="r-due" default>
                <section className="card">
                  <h3 className="card-title">Students with Balance Due ({withBalance.length})</h3>
                  <div className="action-bar">
                    <button className="btn-secondary" onClick={()=>downloadCsv(withBalance,"balance_due.csv")}>↓ Export CSV</button>
                  </div>
                  {withBalance.length===0 ? <Empty text="All students cleared! 🎉"/> : (
                    <Table cols={["PIN","Name","Course","College Bal","Hostel Bal","Total Due","Action"]}
                      rows={withBalance.map(r=>[
                        r.pin, r.name, r.course,
                        `₹${r.collegeBalance}`, `₹${r.hostelBalance}`,
                        <strong style={{color:"var(--red)"}}>₹{r.totalBalance}</strong>,
                        <button className="link-btn" onClick={()=>{setPage("payments");setReceiptPin(r.pin);}}>Pay →</button>
                      ])}/>
                  )}
                </section>
              </SubTab>
              <SubTab id="r-cleared">
                <section className="card">
                  <h3 className="card-title">Cleared Students ({cleared.length})</h3>
                  <div className="action-bar">
                    <button className="btn-secondary" onClick={()=>downloadCsv(cleared,"cleared_students.csv")}>↓ Export CSV</button>
                  </div>
                  {cleared.length===0 ? <Empty text="No cleared students yet"/> : (
                    <Table cols={["PIN","Name","Course","College Paid","Hostel Paid"]}
                      rows={cleared.map(r=>[r.pin,r.name,r.course,`₹${r.collegePaid}`,`₹${r.hostelPaid}`])}/>
                  )}
                </section>
              </SubTab>
              <SubTab id="r-all">
                <section className="card">
                  <h3 className="card-title">All Students ({balanceRows.length})</h3>
                  <div className="action-bar">
                    <input value={pinSearch} onChange={e=>setPinSearch(e.target.value)}
                      placeholder="Filter by PIN…" style={{maxWidth:200}}/>
                    <button className="btn-secondary" onClick={()=>downloadCsv(balanceRows,"all_students.csv")}>↓ Export CSV</button>
                  </div>
                  {balanceRows.length===0 ? <Empty text="No students yet"/> : (
                    <Table cols={["PIN","Name","Course","Total Fee","Paid","Balance","Hostel"]}
                      rows={balanceRows
                        .filter(r=>!pinSearch||String(r.pin).includes(pinSearch))
                        .map(r=>[
                          r.pin, r.name, r.course, `₹${r.collegeTotalFee}`,
                          `₹${r.collegePaid}`,
                          <span style={{color:r.collegeBalance>0?"var(--red)":"var(--green)"}}>₹{r.collegeBalance}</span>,
                          r.hasHostel?<span className="pill green">Yes</span>:<span className="pill">No</span>
                        ])}/>
                  )}
                </section>
              </SubTab>
            </SubTabView>
          </PageShell>
        )}

        {/* ━━━━━━━━━━━━━━━━━━━━━━━━━ ADMIN PAGES ━━━━━━━━━━━━━━━━━━━━━━━━━ */}

        {/* ADMIN: USERS */}
        {isAdmin && activePage==="admin-users" && (
          <PageShell title="User Management" subtitle="Create and manage system users">
            <div className="tab-pills">
              <TabPill id="u-create" label="Create User" default/>
              <TabPill id="u-import" label="Import Users"/>
              <TabPill id="u-list"   label="All Users"/>
            </div>
            <SubTabView>
              <SubTab id="u-create" default>
                <section className="card">
                  <h3 className="card-title">Create New User</h3>
                  <form onSubmit={saveUser} className="form-grid">
                    <Field label="College Code">
                      <input name="collegeKey" list="collegeOpts" placeholder="008"
                        value={createUserForm.collegeKey} onChange={handleInput(setCreateUserForm)}
                        onBlur={()=>setCreateUserForm(p=>({...p,collegeKey:normalizeCollegeCode(p.collegeKey)||"default"}))} required/>
                    </Field>
                    <Field label="Email Address">
                      <input name="email" type="email" placeholder="user@example.com"
                        value={createUserForm.email} onChange={handleInput(setCreateUserForm)} required/>
                    </Field>
                    <Field label="Full Name">
                      <input name="name" placeholder="Full name"
                        value={createUserForm.name} onChange={handleInput(setCreateUserForm)} required/>
                    </Field>
                    <Field label="Role">
                      <select name="role" value={createUserForm.role} onChange={handleInput(setCreateUserForm)}>
                        <option value="staff">Staff</option>
                        <option value="accountant">Accountant</option>
                        <option value="principal">Principal</option>
                        <option value="admin">Admin</option>
                      </select>
                    </Field>
                    <Field label="Password (leave blank to auto-generate)">
                      <input name="password" type="password" placeholder="••••••••"
                        value={createUserForm.password} onChange={handleInput(setCreateUserForm)}/>
                    </Field>
                    <Field label="Status">
                      <select name="active" value={createUserForm.active} onChange={handleInput(setCreateUserForm)}>
                        <option value="true">Active</option>
                        <option value="false">Inactive</option>
                      </select>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Create User</button>
                    </div>
                  </form>
                  <p className="hint">For principal/accountant/staff, leave password blank to auto-generate a temporary password.</p>
                </section>
              </SubTab>
              <SubTab id="u-import">
                <section className="card">
                  <h3 className="card-title">Import Users via Excel / CSV</h3>
                  <div className="action-bar">
                    <button className="btn-secondary" onClick={()=>downloadTemplate("/api/admin/users/template","users_template.csv")}>
                      ↓ Download Template CSV
                    </button>
                  </div>
                  <form onSubmit={importUsers} className="form-grid">
                    <Field label="Select File (.xlsx or .csv)">
                      <input type="file" accept=".xlsx,.xls,.csv" onChange={e=>setImportFile(e.target.files?.[0]||null)} required/>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Upload &amp; Import</button>
                    </div>
                  </form>
                  <div className="info-box" style={{marginTop:12}}>
                    <b>Required columns:</b> collegeKey, email, name, role, password<br/>
                    <b>Optional:</b> active (true/false)<br/>
                    <b>Valid roles:</b> admin, principal, accountant, staff
                  </div>
                </section>
              </SubTab>
              <SubTab id="u-list">
                <section className="card">
                  <h3 className="card-title">All Users ({users.length})</h3>
                  {users.length===0 ? <Empty text="No users found"/> : (
                    <Table cols={["College","Email","Name","Role","Active","Password","Action"]}
                      rows={users.map(u=>[
                        u.collegeKey||"default", u.email, u.name,
                        <span className={`pill ${u.role==="admin"?"red":u.role==="principal"?"blue":""}`}>{u.role}</span>,
                        u.active ? <span className="pill green">Active</span> : <span className="pill red">Inactive</span>,
                        u.mustChangePassword ? <span className="pill red">Must set</span> : <span className="pill green">Set</span>,
                        u.role!=="admin"
                          ? <button className="btn-secondary sm" onClick={()=>resetPassword(u.id)}>Reset PW</button>
                          : "-"
                      ])}/>
                  )}
                </section>
              </SubTab>
            </SubTabView>
          </PageShell>
        )}

        {/* ADMIN: COLLEGES */}
        {isAdmin && activePage==="admin-colleges" && (
          <PageShell title="Colleges" subtitle="Enable or disable college access">
            <section className="card">
              <h3 className="card-title">All Colleges ({colleges.length})</h3>
              <p className="hint" style={{marginBottom:12}}>Disabling a college sets all non-admin users of that college to inactive.</p>
              {colleges.length===0 ? <Empty text="No colleges yet"/> : (
                <Table cols={["College Code","Status","Active / Total Users","Action"]}
                  rows={colleges.map(c=>[
                    c.collegeKey,
                    c.enabled ? <span className="pill green">Enabled</span> : <span className="pill red">Disabled</span>,
                    `${c.activeNonAdmin} / ${c.totalNonAdmin}`,
                    c.enabled
                      ? <button className="btn-secondary sm" onClick={()=>setCollegeActive(c.collegeKey,false)}>Disable</button>
                      : <button className="btn-primary sm" onClick={()=>setCollegeActive(c.collegeKey,true)}>Enable</button>
                  ])}/>
              )}
            </section>
          </PageShell>
        )}

        {/* ADMIN: STUDENTS */}
        {isAdmin && activePage==="admin-students" && (
          <PageShell title="Student Management" subtitle="Add individual students or bulk import">
            <div className="tab-pills">
              <TabPill id="as-add" label="Add Single Student" default/>
              <TabPill id="as-import" label="Bulk Import"/>
            </div>
            <SubTabView>
              <SubTab id="as-add" default>
                <section className="card">
                  <h3 className="card-title">Add Single Student</h3>
                  <form onSubmit={saveAdminStudent} className="form-grid">
                    <Field label="College Code">
                      <input name="collegeKey" list="collegeOpts" placeholder="008"
                        value={adminStudentForm.collegeKey} onChange={handleInput(setAdminStudentForm)}
                        onBlur={()=>setAdminStudentForm(p=>({...p,collegeKey:normalizeCollegeCode(p.collegeKey)}))} required/>
                    </Field>
                    <Field label="PIN / Roll Number">
                      <input name="pin" placeholder="220001" value={adminStudentForm.pin} onChange={handleInput(setAdminStudentForm)} required/>
                    </Field>
                    <Field label="Student Name">
                      <input name="name" placeholder="Full name" value={adminStudentForm.name} onChange={handleInput(setAdminStudentForm)} required/>
                    </Field>
                    <Field label="Course">
                      <input name="course" list="courseOpts" placeholder="COMPUTER ENGINEERING" value={adminStudentForm.course} onChange={handleInput(setAdminStudentForm)} required/>
                    </Field>
                    <Field label="Phone (optional)">
                      <input name="phone" placeholder="9876543210" value={adminStudentForm.phone} onChange={handleInput(setAdminStudentForm)}/>
                    </Field>
                    <Field label="College Total Fee (₹)">
                      <input name="collegeTotalFee" type="number" min="0" placeholder="12000" value={adminStudentForm.collegeTotalFee} onChange={handleInput(setAdminStudentForm)} required/>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Save Student</button>
                    </div>
                  </form>
                </section>
              </SubTab>
              <SubTab id="as-import">
                <section className="card">
                  <h3 className="card-title">Bulk Import Students (Admin — auto-approved)</h3>
                  <div className="action-bar">
                    <button className="btn-secondary" onClick={()=>downloadTemplate("/api/student-imports/template","students_template.csv")}>
                      ↓ Download Template CSV
                    </button>
                  </div>
                  <form onSubmit={submitStudentImport} className="form-grid">
                    <Field label="College Code">
                      <input list="collegeOpts" placeholder="008"
                        value={adminStudentImportCollege}
                        onChange={e=>setAdminStudentImportCollege(e.target.value)}
                        onBlur={()=>setAdminStudentImportCollege(normalizeCollegeCode(adminStudentImportCollege))} required/>
                    </Field>
                    <Field label="Select File (.xlsx or .csv)">
                      <input type="file" accept=".xlsx,.xls,.csv" onChange={e=>setStudentImportFile(e.target.files?.[0]||null)} required/>
                    </Field>
                    <div className="form-actions">
                      <button type="submit" className="btn-primary">Upload &amp; Import (Auto-approve)</button>
                    </div>
                  </form>
                  <p className="hint">Admin imports are auto-approved and directly create/update student records.</p>
                </section>
              </SubTab>
            </SubTabView>
          </PageShell>
        )}

        {/* ADMIN: IMPORTS */}
        {isAdmin && activePage==="admin-imports" && (
          <PageShell title="Student Import Approvals" subtitle="Review and approve pending imports from principals">
            <section className="card">
              <div className="action-bar">
                <button className="btn-secondary" onClick={loadAdminImports}>↻ Refresh</button>
              </div>
              {adminStudentImports.length===0 ? <Empty text="No pending imports"/> : (
                <Table cols={["Date","College","Uploaded By","File","Status","Action"]}
                  rows={adminStudentImports.map(r=>[
                    new Date(r.createdAt).toLocaleString(),
                    r.collegeKey, r.uploadedByEmail, r.originalName,
                    <StatusPill status={r.status}/>,
                    <button className="btn-secondary sm" onClick={async()=>{
                      const d = await callApi(`/api/admin/student-imports/${r._id}`);
                      setSelectedImport(d);
                    }}>Review</button>
                  ])}/>
              )}
            </section>

            {selectedImport && (
              <section className="card" style={{borderColor:"var(--blue)",borderWidth:2}}>
                <div className="import-review-header">
                  <div>
                    <h3 className="card-title" style={{marginBottom:4}}>Review: {selectedImport.originalName}</h3>
                    <p className="hint" style={{margin:0}}>College: {selectedImport.collegeKey} · <StatusPill status={selectedImport.status}/></p>
                  </div>
                  <button className="btn-ghost" onClick={()=>setSelectedImport(null)}>✕ Close</button>
                </div>
                <p className="hint" style={{margin:"8px 0"}}>Showing first {selectedImport.rows?.length||0} of {selectedImport.rowsCount} rows</p>
                {selectedImport.rows?.length ? (
                  <Table cols={["PIN","Name","Course","Phone","Fee","Hostel"]}
                    rows={selectedImport.rows.map(r=>[
                      r.pin, r.name, r.course, r.phone||"-",
                      `₹${r.collegeTotalFee}`,
                      r.hasHostel?<span className="pill green">Yes</span>:"No"
                    ])}/>
                ) : <Empty text="No preview rows"/>}
                {selectedImport.status==="pending" && (
                  <div className="import-actions">
                    <button className="btn-primary" onClick={()=>approveImport(selectedImport._id)}>✓ Approve Import</button>
                    <button className="btn-danger" onClick={()=>rejectImport(selectedImport._id)}>✕ Reject</button>
                  </div>
                )}
              </section>
            )}
          </PageShell>
        )}
      </main>
    </div>
  );
}

/* ─── Small reusable components ────────────────────────────────── */

function PageShell({ title, subtitle, children }) {
  return (
    <div className="page-shell">
      <div className="page-header">
        <h2 className="page-title">{title}</h2>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className={`stat-card stat-${color}`}>
      <span className="stat-icon">{icon}</span>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function QuickAction({ icon, label, onClick }) {
  return (
    <button className="quick-action" onClick={onClick}>
      <span className="qa-icon">{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function Table({ cols, rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{cols.map((c,i)=><th key={i}>{c}</th>)}</tr></thead>
        <tbody>{rows.map((r,i)=><tr key={i}>{r.map((c,j)=><td key={j}>{c}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

function Empty({ text }) {
  return <div className="empty-state"><span>◌</span><p>{text}</p></div>;
}

function Field({ label, children }) {
  return <div className="field"><label className="field-label">{label}</label>{children}</div>;
}

function StatusPill({ status }) {
  return <span className={`pill ${status==="approved"?"green":status==="rejected"?"red":"yellow"}`}>{status}</span>;
}

function ReceiptRow({ label, value, highlight }) {
  return (
    <div className="receipt-row">
      <span className="rr-label">{label}</span>
      <span className={`rr-value ${highlight?"highlight":""}`}>{value}</span>
    </div>
  );
}

/* ── Sub-tab system ─────────────────────────────────────────────── */
let _activeSubTab = {};

function TabPill({ id, label, default: isDefault }) {
  return null; // rendered by SubTabView
}

function SubTabView({ children }) {
  const tabs = Array.isArray(children) ? children.flat().filter(Boolean) : children ? [children] : [];
  const validTabs = tabs.filter(c => c?.props?.id);
  const defaultTab = validTabs.find(c => c?.props?.default)?.props?.id || validTabs[0]?.props?.id;
  const [active, setActive] = useState(defaultTab);

  // Find TabPills by looking at what was rendered by the parent's tab-pills div
  // We reconstruct pill info from the SubTab children
  const pillLabels = {};
  validTabs.forEach(c => {
    if (c?.props?.id) pillLabels[c.props.id] = c.props.label || c.props.id;
  });

  return (
    <>
      <div className="subtab-pills">
        {validTabs.map(c => (
          <button key={c.props.id}
            className={`subtab-pill ${active===c.props.id?"active":""}`}
            onClick={() => setActive(c.props.id)}
          >
            {c.props.label || c.props.id}
          </button>
        ))}
      </div>
      {validTabs.find(c => c.props.id === active)}
    </>
  );
}

function SubTab({ id, label, default: isDefault, children }) {
  return <div className="subtab-content">{children}</div>;
}
