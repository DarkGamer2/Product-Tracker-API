import mongoose from "mongoose";
import { Schema } from "mongoose";
import dotenv from "dotenv";

dotenv.config();

// Define the User schema
const userSchema = new Schema({
    username: { type: String, required: true }, // Add validation
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Email should be unique
    phone: { type: String, required: true },
    created_at: { type: Date, default: Date.now }, 
    isAdmin:{type:Boolean,default:false}// Set default to the current date
});

// Enable virtuals and transform _id to idå
userSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        ret.id = ret._id; // Assign _id to id
        delete ret._id; // Remove _id from the output
        delete ret.__v; // Optionally remove __v (version key)
    },
});

// Connect to the database
mongoose.connect(`${process.env.MONGO_URI}`, {
    
});

// Create the User model
const User = mongoose.model("User", userSchema);

export default User;
