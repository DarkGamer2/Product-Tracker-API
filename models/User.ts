import mongoose from "mongoose";
import { Schema } from "mongoose";
import dotenv from "dotenv";

dotenv.config();
const userSchema=new Schema({
    username: String,
    password:String,
    email: String,
    phone: String,
})

mongoose.connect(`${process.env.MONGO_URI}`)
userSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        ret.id = ret._id; // Assigning _id to id
        delete ret._id;
    }
});
const User= mongoose.model("User",userSchema);

export default User;