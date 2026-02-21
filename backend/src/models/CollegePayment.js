const mongoose = require("mongoose");

const collegePaymentSchema = new mongoose.Schema(
  {
    date: { type: Date, required: true },
    pin: { type: String, required: true, trim: true, index: true },
    amountPaid: { type: Number, required: true, min: 1 }
  },
  { timestamps: true }
);

module.exports = mongoose.model("CollegePayment", collegePaymentSchema);
