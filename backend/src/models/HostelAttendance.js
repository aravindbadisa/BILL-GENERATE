const mongoose = require("mongoose");

const hostelAttendanceSchema = new mongoose.Schema(
  {
    pin: { type: String, required: true, trim: true, index: true },
    month: { type: String, required: true, trim: true, index: true },
    totalDays: { type: Number, required: true, min: 1 },
    daysStayed: { type: Number, required: true, min: 0 },
    calculatedFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

module.exports = mongoose.model("HostelAttendance", hostelAttendanceSchema);
