const mongoose = require("mongoose");

const collegePaymentSchema = new mongoose.Schema(
  {
    date: { type: Date, default: Date.now },
    collegeKey: { type: String, required: true, trim: true, index: true, default: "default" },
    pin: { type: String, required: true, trim: true, index: true },
    amountPaid: { type: Number, required: true, min: 1 },
    phone: { type: String, trim: true, default: "" }
  },
  { timestamps: true }
);

collegePaymentSchema.index({ collegeKey: 1, pin: 1 });

module.exports = mongoose.model("CollegePayment", collegePaymentSchema);
