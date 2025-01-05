export interface productInterface {
    productName: string;
    productPrice: number;
    productImage: string;
}

import { Document } from 'mongoose';

export interface userInterface extends Document {
    username: string 
    password: string 
    email: string | null;
    id: string;
    isAdmin: boolean;
    mobileNumber: string;
    created_at:Date
}

