const mongoose = require("mongoose");

const hostelFeeMasterSchema = new mongoose.Schema(
  {
    collegeKey: { type: String, required: true, trim: true, index: true, default: "default" },
    month: { type: String, required: true, trim: true },
    monthlyFee: { type: Number, required: true, min: 0 }
  },
  { timestamps: true }
);

hostelFeeMasterSchema.index({ collegeKey: 1, month: 1 }, { unique: true });

module.exports = mongoose.model("HostelFeeMaster", hostelFeeMasterSchema);
