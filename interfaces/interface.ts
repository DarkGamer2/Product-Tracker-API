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

