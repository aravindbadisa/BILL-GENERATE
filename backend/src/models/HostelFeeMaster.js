const mongoose = require("mongoose");

const hostelFeeMasterSchema = new mongoose.Schema(
  {
    month: { type: String, required: true, unique: true, trim: true },
    monthlyFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

module.exports = mongoose.model("HostelFeeMaster", hostelFeeMasterSchema);
