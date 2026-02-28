const mongoose = require("mongoose");

const studentImportRowSchema = new mongoose.Schema(
  {
    pin: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    course: { type: String, required: true, trim: true },
    phone: { type: String, trim: true, default: "" },
    hasHostel: { type: Boolean, default: false },
    collegeTotalFee: { type: Number, required: true, min: 0 }
  },
  { _id: false }
);

const studentImportSchema = new mongoose.Schema(
  {
    collegeKey: { type: String, required: true, trim: true, index: true },
    status: {
      type: String,
      required: true,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true
    },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    uploadedByEmail: { type: String, required: true, trim: true, lowercase: true },
    uploadedByRole: { type: String, required: true, trim: true },
    originalName: { type: String, required: true, trim: true },
    mimeType: { type: String, required: true, trim: true },
    size: { type: Number, required: true, min: 0 },
    rowsCount: { type: Number, default: 0, min: 0 },
    rows: { type: [studentImportRowSchema], default: [] },
    result: { type: mongoose.Schema.Types.Mixed, default: null },
    decisionNote: { type: String, trim: true, default: "" },
    decidedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    decidedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

module.exports = mongoose.model("StudentImport", studentImportSchema);
