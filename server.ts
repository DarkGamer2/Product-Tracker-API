import express, { NextFunction, Request, Response } from 'express';
import Product from "./models/Product";
import User from "./models/User";
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
import { TabItem } from './interfaces/interface'; // Assuming you have this interface

const app = express();
const port = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressSession({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
require("./auth/passportConfig")(passport);
app.use(cookieParser("secret_code"));

// Assuming you have this interface defined in interfaces/interface.ts
// export interface productInterface {
//     productName: string;
//     productPrice: number;
//     productImage: string;
// }

// export interface userInterface {
//     username: string | null;
//     password: string | null;
//     email: string | null;
//     id: string;
//     isAdmin?:boolean,
//     mobileNumber:string
// }

// admin initlization
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

function adminOnly(req: any, res: Response, next: NextFunction) {
  if (req.isAuthenticated() && req.user?.isAdmin === true) {
    return next();
  } else {
    return res.status(403).json({ error: "Access denied. Admins only." });
  }
}

// app.get('/products/:barcode', (req, res) => {
//   const { barcode } = req.params;
//   const product = products[barcode];
//   if (product) {
//     res.json(product);
//   } else {
//     res.status(404).json({ error: 'Product not found' });
//   }
// });

app.get("/", (req: Request, res: Response) => {
  res.send("API is working as expected");
});

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
  passport.authenticate("local", (err: Error, user: userInterface, info: any, message: string) => {
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

app.post('/api/logout', (req: Request, res: Response) => {
  req.logOut((err: Error) => {
    if (err) {
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
      mobileNumber: user.mobileNumber,
      isAdmin: user.isAdmin // Convert _id to string
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
      mobileNumber: req.body.mobileNumber, // Assuming mobileNumber is now part of registration
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
  const { productName, productPrice, productImage } = req.body;
  if (!productName || typeof productPrice !== 'number' || !productImage) {
    return res.status(400).json({ error: 'Product name, price, and image are required.' });
  }
  const newProduct = new Product({
    productName,
    productPrice,
    productImage,
  });
  try {
    const savedProduct = await newProduct.save();
    res.json({ message: 'Product added successfully', product: savedProduct });
    console.log(savedProduct);
  } catch (error: any) {
    console.error('Error adding product:', error);
    res.status(500).json({ error: 'Failed to add product', details: error.message });
  }
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
      return res.json({ status: 404, message: "User not found" });
    }
    res.json(user);
  } catch (err: any) {
    res.json({ status: 404, message: `${err.message}` });
  }
});

app.get('/api/tabs/customer/:customerId', async (req: Request, res: Response) => {
  const customerId = req.params.customerId;

  if (!mongoose.Types.ObjectId.isValid(customerId)) {
    return res.status(400).json({ error: "Invalid customer ID" });
  }

  try {
    const tab = await Tab.findOne({ customer_id: customerId }).exec();
    if (tab) {
      res.json(tab);
    } else {
      res.status(200).json({ message: "No existing tab found for this customer", tab: null }); // Return null if not found
    }
  } catch (error: any) {
    console.error('Error fetching tab:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post("/api/tabs", async (req: Request, res: Response) => {
  const { customerId, tabItems } = req.body;

  if (!customerId) {
    return res.status(400).json({ error: "Customer ID is required" });
  }
  if (!mongoose.Types.ObjectId.isValid(customerId)) {
    return res.status(400).json({ error: "Invalid customer ID" });
  }
  if (!tabItems || !Array.isArray(tabItems)) {
    return res.status(400).json({ error: "tabItems must be an array" });
  }

  try {
    const newTab = new Tab({
      customer_id: customerId,
      tabItems: tabItems,
    });

    const savedTab = await newTab.save();
    res.status(201).json({ message: "Tab created successfully", tab: savedTab });
  } catch (error: any) {
    console.error("Error creating tab:", error);
    res.status(500).json({ error: "Failed to create tab", details: error.message });
  }
});

app.put("/api/tabs/:tabId", async (req: Request, res: Response) => {
  const tabId = req.params.tabId;
  const { tabItems } = req.body;

  if (!mongoose.Types.ObjectId.isValid(tabId)) {
    return res.status(400).json({ error: "Invalid tab ID" });
  }
  if (!tabItems || !Array.isArray(tabItems)) {
    return res.status(400).json({ error: "tabItems must be an array" });
  }

  try {
    const updatedTab = await Tab.findByIdAndUpdate(
      tabId,
      { $set: { tabItems: tabItems } },
      { new: true }
    ).exec();

    if (!updatedTab) {
      return res.status(404).json({ error: "Tab not found" });
    }

    res.json({ message: "Tab updated successfully", tab: updatedTab });
  } catch (error: any) {
    console.error("Error updating tab:", error);
    res.status(500).json({ error: "Failed to update tab", details: error.message });
  }
});
app.post('/api/tabs/:tabId', async (req: Request, res: Response) => {
  try {
    const tab = new Tab(req.body);
    await tab.save();
    res.status(201).json(tab); // ✅ Respond to the client!
  } catch (error) {
    console.error('Error saving tab:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.get('/api/tabs/:tabId', async (req: Request, res: Response) => {
  const { tabId } = req.params;

  try {
    const tab = await Tab.findOne({ customer_id: new mongoose.Types.ObjectId(tabId) });

    if (!tab) {
      return res.status(404).json({ message: 'Tab not found' });
    }

    return res.status(200).json(tab);
  } catch (error) {
    console.error('Error fetching tab:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/products/:barcode', async (req: Request, res: Response) => {
  const barcode = req.params.barcode;

  try {
    const product = await Product.findOne({ barcode: barcode }).exec();

    if (product) {
      res.json({ product });
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    console.error('Error fetching product by barcode:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/products/:barcode', async (req: Request, res: Response) => {
  const barcode = req.params.barcode;

  // Check if the user is authenticated
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'Unauthorized: Please log in to add items to your tab.' });
  }

  // Get the current user's ID
  const userId = (req.user as userInterface)?.id || null;

  if (!userId) {
    return res.status(500).json({ message: 'Could not retrieve user ID.' });
  }

  try {
    // ... rest of the function implementation ...
  } catch (error) {
    console.error('Error adding product to tab:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/api/products/:id', async (req: Request, res: Response) => {
  const id = req.params.id;
  try {
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

app.put("/api/users/adminAccess", adminOnly, async (req: Request, res: Response) => {
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
  console.log(`Server is running on port ${port}`);
});