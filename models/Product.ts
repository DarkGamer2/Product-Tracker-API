import { Schema } from "mongoose";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

mongoose.connect(`${process.env.MONGO_URI}`);

const productSchema = new Schema({
  productName: String,
  productPrice: Number,
  productImage: String,
  productDescription: String,
  barcode: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }, // Link to Admin
  createdAt: { type: Date, default: Date.now },
  tenant_id: { type: String, required: true }, // Add tenant_id field
});

const Product = mongoose.model("Product", productSchema);

export default Product;