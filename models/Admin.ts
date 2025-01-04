import { Schema } from "mongoose";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

mongoose.connect(`${process.env.MONGO_URI}`)
const adminSchema = new Schema({
    adminUsername: { type: String, required: true }, // Add validation
    adminPassword: { type: String, required: true },
    adminEmail: { type: String, required: true, unique: true }, // Ensure unique email
    adminPhoneNumber: { type: Number, required: true },
    created_at: { type: Date, default: Date.now }, // Dynamically set current date
});

// Enable virtuals and transform _id to id
adminSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        ret.id = ret._id; // Replace _id with id
        delete ret._id; // Remove _id from the output
        delete ret.__v; // Remove the version key (__v)
    },
});

export default adminSchema;
