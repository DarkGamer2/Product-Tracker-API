import { Schema } from "mongoose";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config()
mongoose.connect(`${process.env.MONGO_URI}`)
const productSchema = new Schema({
  productName: String,
  productPrice: Number,
  productImage: String,
  productDescription:String
});

const Product = mongoose.model("Product", productSchema);

export default Product;