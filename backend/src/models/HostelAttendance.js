const mongoose = require("mongoose");

const hostelAttendanceSchema = new mongoose.Schema(
  {
    collegeKey: { type: String, required: true, trim: true, index: true, default: "default" },
    pin: { type: String, required: true, trim: true, index: true },
    month: { type: String, required: true, trim: true, index: true },
    totalDays: { type: Number, required: true, min: 1 },
    daysStayed: { type: Number, required: true, min: 0 },
    calculatedFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

hostelAttendanceSchema.index({ collegeKey: 1, pin: 1, month: 1 }, { unique: true });

module.exports = mongoose.model("HostelAttendance", hostelAttendanceSchema);
