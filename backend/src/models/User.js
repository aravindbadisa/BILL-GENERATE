const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    collegeKey: { type: String, trim: true, default: "default", index: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    name: { type: String, required: true, trim: true },
    role: {
      type: String,
      required: true,
      enum: ["admin", "principal", "accountant", "staff"],
      default: "staff"
    },
    passwordHash: { type: String, required: true },
    mustChangePassword: { type: Boolean, default: false },
    active: { type: Boolean, default: true }
  },
  { timestamps: true }
);

userSchema.index(
  { collegeKey: 1, role: 1 },
  { unique: true, partialFilterExpression: { role: "principal" } }
);

module.exports = mongoose.model("User", userSchema);
