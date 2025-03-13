import express, { NextFunction, Request, Response } from 'express';
import Product from "./models/Product"
import User from "./models/User"
import { productInterface, userInterface } from './interfaces/interface';
import bcrypt from "bcryptjs";
import cors from "cors";
import expressSession from "express-session";
import cookieParser from 'cookie-parser';
import passport from 'passport';
import path from "path";
import mongoose from 'mongoose';
import Report from './models/Feedback';
import Tab from './models/Tab';
const app = express();
const port=process.env.PORT||3000;
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

function adminOnly(req:any, res:Response, next:NextFunction) {
  const user=new User();
  if (req.isAuthenticated() && req.user?.isAdmin===true) {
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
  const { username, password, email, mobileNumber } = req.body;

  // Check for missing fields
  if (!username || !password || !email || !mobileNumber) {
      return res.status(400).json({ error: "All fields are required: username, password, email, mobileNumber" });
  }

  try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
          return res.status(400).json({ error: "User with that username already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
          username,
          password: hashedPassword,
          email,
          mobileNumber
      });

      await newUser.save();
      res.status(200).json({ message: "User registered successfully" });
  } catch (error) {
      console.error("Registration Error:", error);
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
      isAdmin:user.isAdmin// Convert _id to string
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
      return res.json({ status: 404, message:"User not found"})
    }
    res.json(user);
  } catch (err:any) {
    res.json({ status: 404, message: `${err.message}`})
  }
});

// app.get('/api/users/:id', async (req: Request, res: Response) => {
//   const userId = req.query.id as string; // Assuming user ID is passed as a query parameter

//   if (!userId) {
//     return res.status(400).json({ error: 'User ID is required' });
//   }

//   // Validate ObjectId
//   if (!mongoose.Types.ObjectId.isValid(userId)) {
//     return res.status(400).json({ error: 'Invalid User ID' });
//   }

//   try {
//     const user = await User.findById(userId).exec();
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }
//     res.json(user);
//   } catch (error) {
//     console.error('Error querying the database:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

app.post("/api/tabs/:id", async (req: Request, res: Response) => {
  const id = req.params.id;

  // Validate customer_id if it's an ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid customer ID" });
  }

  // Validate request body
  if (!req.body || !req.body.tabItems || !req.body.customer_name) {
    return res
      .status(400)
      .json({ error: "Missing tabItems or customer_name in request body" });
  }

  try {
    const tab = new Tab({
      customer_id: id,
      tabItems: req.body.tabItems, // Use tabItems from request
      customer_name: req.body.customer_name,
    });

    await tab.save();

    res.status(201).json({ message: "Tab saved successfully" });
  } catch (error: any) {
    console.error("Error saving tab:", error);
    res
      .status(500)
      .json({ error: "Failed to save tab", details: error.message });
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

app.get('/api/products/:id',async (req:Request, res:Response) => {
  const id = req.params.id;
  try{
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(product);
  }catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
})
app.post("/api/feedback", async (req: Request, res: Response) => {
  try {
    const report = new Report(req.body);
    await report.save();
    res.sendStatus(200); // Use sendStatus to send a proper HTTP status code
  } catch (error) { // Correctly place the catch block
    console.error("Error saving feedback:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/users/adminAccess", async (req: Request, res: Response) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "Username is required" });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.isAdmin) {
      return res.status(400).json({ error: "User already has admin access" });
    }

    user.isAdmin = true;
    await user.save();

    return res.status(200).json({ message: "User granted admin access", user });
  } catch (error) {
    console.error("Error updating admin access:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/users/adminAccess", async (req: Request, res: Response) => {
  try {
    const { username } = req.body;

    // Validate input
    if (!username) {
      return res.status(400).json({ error: "Username is required" });
    }

    // Check if the user exists
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the user has admin access
    if (user.isAdmin) {
      return res.status(200).json({ isAdmin: true, message: "User has admin access" });
    } else {
      return res.status(200).json({ isAdmin: false, message: "User does not have admin access" });
    }
  } catch (error) {
    console.error("Error checking admin status:", error);
    return res.status(500).json({ error: "Something went wrong" });
  }
});
app.put("/api/users/resetPassword", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Validate the input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: "Password has been reset successfully." });
  } catch (err) {
    console.error("Error during password reset request:", err);
    return res.status(500).json({ message: "Error on the server." });
  }
});
app.listen(port, () => {
    console.log('Server is running on port 4040');
});

