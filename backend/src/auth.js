const jwt = require("jsonwebtoken");

const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is missing in environment variables");
  return secret;
};

const signToken = (user) => {
  const secret = getJwtSecret();
  return jwt.sign(
    { sub: String(user._id), role: user.role, email: user.email, name: user.name },
    secret,
    { expiresIn: "7d" }
  );
};

const authRequired = (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const [type, token] = header.split(" ");
    if (type !== "Bearer" || !token) {
      return res.status(401).json({ message: "Missing Bearer token" });
    }
    const payload = jwt.verify(token, getJwtSecret());
    req.auth = payload;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

const roleRequired = (role) => (req, res, next) => {
  if (!req.auth) return res.status(401).json({ message: "Unauthorized" });
  if (req.auth.role !== role) return res.status(403).json({ message: "Forbidden" });
  next();
};

const anyRoleRequired = (roles) => (req, res, next) => {
  if (!req.auth) return res.status(401).json({ message: "Unauthorized" });
  if (!roles.includes(req.auth.role)) return res.status(403).json({ message: "Forbidden" });
  next();
};

module.exports = { signToken, authRequired, roleRequired, anyRoleRequired };
