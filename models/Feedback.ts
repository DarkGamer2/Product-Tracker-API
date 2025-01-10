import mongoose, { Schema } from "mongoose";

const feedbackSchema=new Schema({
    firstName:String,
    lastName:String,
    feedback:String,
    createdAt: { type: Date, default: Date.now },
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer' },
})

const Report=mongoose.model("Report",feedbackSchema)
export default Report;