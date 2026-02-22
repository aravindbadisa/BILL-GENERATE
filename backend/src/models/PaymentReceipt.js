const mongoose = require("mongoose");

const paymentReceiptSchema = new mongoose.Schema(
  {
    receiptNo: { type: String, required: true, trim: true, unique: true, index: true },
    accessKey: { type: String, required: true, trim: true },

    collegeKey: { type: String, required: true, trim: true, index: true, default: "default" },
    pin: { type: String, required: true, trim: true, index: true },

    paymentType: { type: String, required: true, enum: ["college", "hostel", "combined"] },
    // Legacy single-line receipt fields
    amountPaid: { type: Number, required: true },
    month: { type: String, trim: true, default: "" }, // hostel month (optional)

    // Combined receipt lines (optional, used when paymentType=combined)
    items: {
      type: [
        {
          type: {
            type: String,
            enum: ["college", "hostel"],
            required: true
          },
          month: { type: String, trim: true, default: "" },
          amount: { type: Number, required: true }
        }
      ],
      default: undefined
    },

    paymentDate: { type: Date, required: true },
    createdBy: { type: String, required: true, trim: true },

    // Snapshot at time of payment (for display only; does not affect billing logic)
    studentName: { type: String, trim: true, default: "" },
    course: { type: String, trim: true, default: "" },
    phone: { type: String, trim: true, default: "" },
    collegeName: { type: String, trim: true, default: "" }
  },
  { timestamps: true }
);

paymentReceiptSchema.index({ collegeKey: 1, pin: 1, paymentDate: -1 });

module.exports = mongoose.model("PaymentReceipt", paymentReceiptSchema);
