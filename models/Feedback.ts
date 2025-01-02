import mongoose, { Schema } from "mongoose";

const feedbackSchema=new Schema({
    firstName:String,
    lastName:String,
    feedback:String
})

const Report=mongoose.model("Report",feedbackSchema)
export default Report;