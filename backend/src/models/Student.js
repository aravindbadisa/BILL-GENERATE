const mongoose = require("mongoose");

const studentSchema = new mongoose.Schema(
  {
    pin: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true, trim: true },
    course: { type: String, required: true, trim: true },
    collegeTotalFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Student", studentSchema);
