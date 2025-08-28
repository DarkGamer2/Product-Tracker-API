import mongoose, { Schema, Document } from 'mongoose';

export interface IAdmin extends Document {
  username: string;
  password: string;
  email: string;
  phoneNumber: string;
  createdAt: Date;
  updatedAt: Date;
}

const adminSchema = new Schema<IAdmin>({
  username: { type: String, required: true },
  password: { type: String, required: true }, // Hash this!
  email: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true },
}, { timestamps: true });

adminSchema.set('toJSON', {
  virtuals: true,
  transform: (_, ret) => {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    delete ret.password; // Hide password hash
  },
});

export default mongoose.model<IAdmin>('Admin', adminSchema);
