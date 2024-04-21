import { Schema } from "mongoose";
import mongoose from "mongoose";
const productSchema = new Schema({
  productName: String,
  productPrice: Number,
  productImage: String,
});

const Product = mongoose.model("Product", productSchema);

export default Product;