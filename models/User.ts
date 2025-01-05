import mongoose, { Schema, Document } from "mongoose";
import { userInterface } from "../interfaces/interface"; // Import userInterface

// Define the User schema
const userSchema = new Schema<userInterface>({
    username: { type: String, required: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    mobileNumber: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
    isAdmin: { type: Boolean, default: false }, // Default value for isAdmin
});

// Enable virtuals and transform _id to id
userSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        ret.id = ret._id; // Assign _id to id
        delete ret._id; // Remove _id from the output
        delete ret.__v; // Optionally remove __v (version key)
    },
});

// Create the User model and apply the userInterface
const User = mongoose.model<userInterface>("User", userSchema);

export default User;
