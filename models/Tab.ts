import mongoose from "mongoose";
import { Schema } from "mongoose";
import dotenv from "dotenv";
dotenv.config();
mongoose.connect(`${process.env.MONGO_URI}`)
const productSchema = new Schema({
    product_id: { type: mongoose.Schema.Types.ObjectId, required: true },
    product_name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true },
    payment_status: { type: String, enum: ['pending', 'on credit', 'paid'], default: 'pending' },
  });
  
  const tabSchema = new Schema({
    customer_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
    customer_name: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
    tabItems: [productSchema],
    status: { type: String, enum: ['pending', 'closed'], default: 'pending' },
    updated_at: { type: Date, default: Date.now },
  });
  
  const Tab = mongoose.model('Tab', tabSchema);

  export default Tab;