const mongoose = require("mongoose");

const studentSchema = new mongoose.Schema(
  {
    collegeKey: { type: String, required: true, trim: true, index: true },
    pin: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    course: { type: String, required: true, trim: true },
    phone: { type: String, trim: true, default: "" },
    hasHostel: { type: Boolean, default: false },
    collegeTotalFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

studentSchema.index({ collegeKey: 1, pin: 1 }, { unique: true });

module.exports = mongoose.model("Student", studentSchema);
