import mongoose from "mongoose";
export interface productInterface {
    productName: string;
    productPrice: number;
    productImage: string;
}

export interface userInterface {
    username: string | null;
    password: string | null;
    email: string | null;
    id: string;
    isAdmin?:boolean,
    mobileNumber:string
}

export interface TabItem {
    product_id: mongoose.Schema.Types.ObjectId;
    product_name: string;
    price: number;
    quantity: number;
    payment_status?: 'pending' | 'on credit' | 'paid';
  }
  



