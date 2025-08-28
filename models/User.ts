import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
  username: string;
  password: string;
  email: string;
  mobileNumber: string;
  isAdmin: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>({
  username: { type: String, required: true },
  password: { type: String, required: true },  // Remember to hash!
  email: { type: String, required: true, unique: true },
  mobileNumber: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });

userSchema.set('toJSON', {
  virtuals: true,
  transform: (_, ret) => {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    delete ret.password; // Never send password hash to client
  },
});

export default mongoose.model<IUser>('User', userSchema);
