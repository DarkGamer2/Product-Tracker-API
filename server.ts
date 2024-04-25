import express, { NextFunction, Request, Response } from 'express';
import Product from "./models/Product"
import User from "./models/User"
import { productInterface, userInterface } from './interfaces/interface';
import bcrypt from "bcrypt";
import cors from "cors";
import expressSession from "express-session";
import cookieParser from 'cookie-parser';
import passport from 'passport';
import path from "path";
const app = express();
const PORT=process.env.PORT||3000;
app.use(cors());
app.use(express.json()); 
app.use(express.urlencoded({extended: true}));
app.use(expressSession({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
require("./auth/passportConfig")(passport)

app.use(cookieParser("secret_code"));

const products = [
    { barcode: '1003602101', name: 'Blue Waters', price: 10.99 },
    { barcode: '987654321', name: 'Product B', price: 5.99 },
    {barcode: '0474100688', name: 'Notebook', price: 5.99}
    // Add more products as needed
  ];

  app.get("/",(req:Request,res:Response)=>{
    res.send("API is working as expected");
  })
app.post('/api/products', (req: Request, res: Response) => {
    const product = new Product(req.body);
    product.save();
    res.send(200);
});

app.get('/api/products', (req: Request, res: Response)=>{
    const { barcode } = req.query;
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode parameter is required' });
    }
  
    // Find product with matching barcode
    const product = products.find(product => product.barcode === barcode);
  
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
  
    // Return product information
    res.json(product);
    app.get("/api/username", (req:Request, res:Response) => {
        // const {username}=req.userInterface;
    })
  });

  app.post("/api/register", async (req: Request, res: Response) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user) {
            console.log("User with that username already exists");
            return res.status(400).send("User with that username already exists");
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({
            username: req.body.username,
            password: hashedPassword,
        });

        await newUser.save();
        console.log("User registered successfully");
        res.status(200).send("User registered successfully");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post('/api/login', (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate("local", (err: Error, user: userInterface, info: any,message:string) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(401).json({ err: "No user exists!" }); // Send JSON response
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            return res.status(200).json({ message: "User logged in successfully!" }); // Send JSON response
        });
    })(req, res, next);
});

app.post('/api/logout',(req:Request, res:Response) => {
    req.logOut((err:Error)=>{
        if(err){
            return res.status(500).send("Internal Server Error");
        }
        return res.status(200).send("User logged out successfully");
    });
    res.status(200).json({ message: "User logged out successfully!" }); // Send JSON response
});
app.listen(port, "0.0.0.0", () => {
    console.log('Server is running on port 4040');
});
