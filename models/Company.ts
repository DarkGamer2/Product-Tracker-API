import { Schema } from "mongoose";
import mongoose from "mongoose";

const companySchema=new Schema({
name:{type:String, required:true},
tenant_id:{type:String,unique:true,required:true},
owner:{type:mongoose.Schema.Types.ObjectId,ref:"User"},
subscription_status: { type: String, default: "trial" }, // active, trial, canceled
    createdAt: { type: Date, default: Date.now }
});

const Company=mongoose.model("Company",companySchema)


export default Company;