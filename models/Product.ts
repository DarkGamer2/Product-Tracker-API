import { Schema } from "mongoose";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config()
mongoose.connect(`${process.env.MONGO_URI}`)
const productSchema = new Schema({
  productName: String,
  productPrice: Number,
  productImage: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

const Product = mongoose.model("Product", productSchema);

export default Product;