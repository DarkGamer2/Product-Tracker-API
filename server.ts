import express, { NextFunction, Request, Response } from 'express';
import Product from "./models/Product"
import User from "./models/User"
import Tab from "./models/Tab";
import { productInterface, userInterface } from './interfaces/interface';
import bcrypt from "bcryptjs";
import cors from "cors";
import expressSession from "express-session";
import cookieParser from 'cookie-parser';
import passport from 'passport';
import path from "path";
import mongoose from 'mongoose';
import Report from './models/Feedback';
const app = express();
const port=process.env.PORT||3000;
app.use(cors());
app.use(express.json()); 
app.use(express.urlencoded({extended: true}));
// app.use(expressSession({
//   secret: 'your_secret_key',
//   resave: false,
//   saveUninitialized: true
// }));
app.use(passport.session());
require("./auth/passportConfig")(passport)

app.use(cookieParser("secret_code"));

interface Product {
    barcode: string;
    name: string;
    price: number;
  }
  
  const products: { [key: string]: Product } = {
    '123456789012': { barcode: '123456789012', name: 'Product 1', price: 10 },
    '123456789013': { barcode: '123456789013', name: 'Product 2', price: 15 },
    '123456789014': { barcode: '123456789014', name: 'Product 3', price: 20 },
    '123456789015': { barcode: '123456789015', name: 'Product 4', price: 25 }
  };
  
  //admin initlization
  async function ensureTestAdmin() {
    const testUsername = "Tester"; // Replace with your test account username
    const testUser = await User.findOne({ username: testUsername });

    if (testUser && !testUser.isAdmin) {
        testUser.isAdmin = true;
        await testUser.save();
        console.log("Test user is now an admin.");
    } else if (!testUser) {
        console.log("Test user not found.");
    }
}

ensureTestAdmin().catch(console.error);

function adminOnly(req:Request, res:Response, next:NextFunction) {
  const user=new User();
  if (req.isAuthenticated() && user.isAdmin===true) {
      return next();
  } else {
      return res.status(403).json({ error: "Access denied. Admins only." });
  }
}

  app.get('/products/:barcode', (req, res) => {
    const { barcode } = req.params;
    const product = products[barcode];
    if (product) {
      res.json(product);
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  });

  app.get("/",(req:Request,res:Response)=>{
    res.send("API is working as expected");
  })
// app.post('/api/products', (req: Request, res: Response) => {
//     const product = new Product(req.body);
//     product.save();
//     res.send(200);
// });



  app.post("/api/register", async (req: Request, res: Response) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user) {
            console.log("User with that username already exists");
            res.status(400).json({ error: "User with that username already exists" });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({
            username: req.body.username,
            password: hashedPassword,
            email: req.body.email,
            mobileNumber: req.body.mobileNumber
        });

        await newUser.save();
        console.log("User registered successfully");
        res.status(200).json({ message: "User registered successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error" });
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

app.get('/api/customers', async (req: Request, res: Response) => {
  try {
    // Fetch all users
    const users = await User.find().lean().exec();
    
    // Transform documents to match userInterface
    const transformedUsers: userInterface[] = users.map(user => ({
      username: user.username ?? null,
      password: user.password ?? null,
      email: user.email ?? null,
      id: user._id.toString(), 
      mobileNumber:user.mobileNumber,
      isAdmin:user.isAdmin,// Convert _id to string
      created_at:user.created_at
    }));
    
    if (transformedUsers.length === 0) {
      return res.status(404).send('No users found.');
    }
    
    // Send the array of users
    res.json(transformedUsers);
  } catch (err) {
    // Handle errors
    console.error(err);
    res.status(500).send('Error on the server.');
  }
});

app.post('/api/customers', async (req: Request, res: Response) => {
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email: req.body.email }).exec();
    
    if (existingUser) {
      return res.status(400).send('User already exists.');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    // Create a new user
    const newUser = new User({
      username: req.body.username,
      password: hashedPassword,
      email: req.body.email,
    });

    // Save the new user
    const savedUser = await newUser.save();

    // Respond with success message and user data
    res.json({ message: 'User created successfully', user: savedUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error on the server.');
  }
});

app.post('/api/products/addProduct', adminOnly, async (req: Request, res: Response) => {
 const product=new Product(req.body);
 await product.save();
 res.json({ message: 'Product added successfully', product });
 console.log(product);
});
app.get('/api/products', async (req: Request, res: Response) => {
  try {
    const products = await Product.find({}).exec();
    res.json(products);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/api/users/:id', async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.params.id).exec();
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.get('/api/users/:id', async (req: Request, res: Response) => {
  const userId = req.query.id as string; // Assuming user ID is passed as a query parameter

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid User ID' });
  }

  try {
    const user = await User.findById(userId).exec();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error querying the database:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/products/:barcode', async (req: Request, res: Response) => {
  const barcode = req.params.barcode;

  try {
    const product = await Product.findOne({ barcode: barcode });

    if (product) {
      res.json({ message: 'Product found', product });
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/products/:barcode', async (req: Request, res: Response) => {
  const barcode = req.params.barcode;
  const productData = req.body;

  try {
    const product = await Product.findOneAndUpdate(
      { barcode: barcode }, // Find product by barcode
      productData,
      { new: true, upsert: true } // Create a new document if no match is found
    );

    res.json({ message: 'Product added/updated successfully', product });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post("/api/feedback",(req:Request,res:Response)=>{
  const report=new Report(req.body);
  report.save();
  res.send(200)
})
app.listen(port, () => {
    console.log('Server is running on port 4040');
});

