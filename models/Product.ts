import mongoose, { Schema, Document } from 'mongoose';

export interface IProduct extends Document {
  productName: string;
  productPrice: number;
  productImage?: string;
  productDescription?: string;
  barcode?: string;
  createdBy: mongoose.Types.ObjectId; // Admin reference
  companyId: mongoose.Types.ObjectId; // Company reference
  categoryId?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const productSchema = new Schema<IProduct>({
  productName: { type: String, required: true },
  productPrice: { type: Number, required: true },
  productImage: String,
  productDescription: String,
  barcode: String,
  createdBy: { type: Schema.Types.ObjectId, ref: 'Admin', required: true },
  companyId: { type: Schema.Types.ObjectId, ref: 'Company', required: true },
  categoryId: { type: Schema.Types.ObjectId, ref: 'Category' },
}, { timestamps: true });

productSchema.set('toJSON', {
  virtuals: true,
  transform: (_, ret) => {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
  },
});

export default mongoose.model<IProduct>('Product', productSchema);
