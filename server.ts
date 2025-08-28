import express, { NextFunction, Request, Response } from "express";
import Product from "./models/Product";
import User from "./models/User";
import { productInterface, userInterface } from "./interfaces/interface";
import bcrypt from "bcryptjs";
import cors from "cors";
import expressSession from "express-session";
import cookieParser from "cookie-parser";
import passport from "passport";
import path from "path";
import mongoose from "mongoose";
import Report from "./models/Feedback";
import Tab from "./models/Tab";
import { TabItem } from "./interfaces/interface"; // Assuming you have this interface
import jwt from "jsonwebtoken";
import "./auth/jwtConfig";
import Company from "./models/Company";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
// Implement rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests, please try again later.",
});

const app = express();
// Apply the rate limiting middleware to all API requests
app.use("/api/", apiLimiter);

// Implement PayPal payment
// Implement commercialized endpoints for product management for businesses
// Add SKU support for products

// Extend express-session to include 'user' property
declare module "express-session" {
  interface SessionData {
    user?: { username: string };
  }
}

const port = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  expressSession({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
require("./auth/passportConfig")(passport);
app.use(cookieParser("secret_code"));

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

app.get("/", (req: Request, res: Response) => {
  res.send("API is working as expected");
});

app.post(
  "/api/register",
  [
    body("username").notEmpty().withMessage("Username is required"),
    body("password").notEmpty().withMessage("Password is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("mobileNumber").notEmpty().withMessage("Mobile number is required"),
  ],
  async (req: Request, res: Response) => {
    const { username, password, email, mobileNumber } = req.body;

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Check for missing fields
    if (!username || !password || !email || !mobileNumber) {
      return res.status(400).json({
        error:
          "All fields are required: username, password, email, mobileNumber",
      });
    }

    try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res
          .status(400)
          .json({ error: "User with that username already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        username,
        password: hashedPassword,
        email,
        mobileNumber,
      });

      await newUser.save();
      res.status(200).json({ message: "User registered successfully" });
    } catch (error) {
      console.error("Registration Error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

app.post("/api/logout", (req: Request, res: Response) => {
  req.logOut((err: Error) => {
    if (err) {
      return res.status(500).send("Internal Server Error");
    }
    return res.status(200).send("User logged out successfully");
  });
  res.status(200).json({ message: "User logged out successfully!" }); // Send JSON response
});

app.get(
  "/api/protected",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({ message: "This is a protected route", user: req.user });
  }
);

app.get("/api/customers", async (req: Request, res: Response) => {
  try {
    // Fetch all users
    const users = await User.find().lean().exec();

    // Transform documents to match userInterface
    const transformedUsers: userInterface[] = users.map((user) => ({
      username: user.username ?? null,
      password: user.password ?? null,
      email: user.email ?? null,
      id: user._id.toString(),
      mobileNumber: user.mobileNumber,
      companyId: (user as any).companyId
        ? (user as any).companyId.toString()
        : "", // Ensure companyId is a string
      isAdmin: user.isAdmin, // Convert _id to string
    }));

    if (transformedUsers.length === 0) {
      return res.status(404).send("No users found.");
    }

    // Send the array of users
    res.json(transformedUsers);
  } catch (err) {
    // Handle errors
    console.error(err);
    res.status(500).send("Error on the server.");
  }
});

app.post("/api/customers", async (req: Request, res: Response) => {
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email: req.body.email }).exec();

    if (existingUser) {
      return res.status(400).send("User already exists.");
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
    res.json({ message: "User created successfully", user: savedUser });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error on the server.");
  }
});

app.post(
  "/api/products/addProduct",
  adminOnly,
  [
    body("productName").notEmpty().withMessage("Product name is required"),
    body("productPrice")
      .isNumeric()
      .withMessage("Product price must be a number"),
    body("productImage").notEmpty().withMessage("Product image is required"),
    body("productDescription")
      .optional()
      .isString()
      .withMessage("Product description must be a string"),
  ],
  async (req: Request, res: Response) => {
    const { productName, productPrice, productImage } = req.body;
    if (!productName || typeof productPrice !== "number" || !productImage) {
      return res
        .status(400)
        .json({ error: "Product name, price, and image are required." });
    }
    const newProduct = new Product({
      productName,
      productPrice,
      productImage,
    });
    try {
      const savedProduct = await newProduct.save();
      res.json({
        message: "Product added successfully",
        product: savedProduct,
      });
      console.log(savedProduct);
    } catch (error: any) {
      console.error("Error adding product:", error);
      res
        .status(500)
        .json({ error: "Failed to add product", details: error.message });
    }
  }
);

app.get("/api/users/:userId", async (req: Request, res: Response) => {
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

app.get(
  "/api/tabs/customer/:customerId",
  async (req: Request, res: Response) => {
    const customerId = req.params.customerId;

    if (!mongoose.Types.ObjectId.isValid(customerId)) {
      return res.status(400).json({ error: "Invalid customer ID" });
    }

    try {
      const tab = await Tab.findOne({ customer_id: customerId }).exec();
      if (tab) {
        res.json(tab);
      } else {
        res.status(200).json({
          message: "No existing tab found for this customer",
          tab: null,
        }); // Return null if not found
      }
    } catch (error: any) {
      console.error("Error fetching tab:", error);
      res
        .status(500)
        .json({ error: "Internal server error", details: error.message });
    }
  }
);

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
    res
      .status(500)
      .json({ error: "Failed to update tab", details: error.message });
  }
});
app.post("/api/tabs", async (req: Request, res: Response) => {
  const { customer_id, customer_name, tabItems } = req.body;
  console.log("Received tab data:", { customer_id, customer_name, tabItems });
  // Check for top-level required fields (customer_id, customer_name, tabItems)
  if (!customer_id || !customer_name || !Array.isArray(tabItems)) {
    return res.status(400).json({
      message:
        "Missing required fields: customer_id, customer_name, or tabItems must be an array.",
    });
  }

  // Default values for optional fields
  const fallbackCustomerName = customer_name || "Unknown Customer";

  // Process each tab item and apply fallback data
  const updatedTabItems = tabItems.map((item) => {
    return {
      product_id: item.product_id || "default-product-id", // Fallback for missing product_id
      product_name: item.product_name || "Default Product", // Fallback for missing product_name
      price: item.price ?? 0, // Default price to 0 if missing or invalid
      quantity: item.quantity ?? 1, // Default quantity to 1 if missing
    };
  });

  // Check if any required fields are missing from each tab item (using the processed tab items)
  const missingFields = updatedTabItems.filter((item) => {
    return (
      !item.product_id ||
      !item.product_name ||
      item.price === undefined ||
      item.quantity === undefined
    );
  });

  if (missingFields.length > 0) {
    return res.status(400).json({
      message:
        "Each tabItem must include: product_id, product_name, price, and quantity.",
    });
  }

  try {
    // Create a new tab with the fallback data
    const newTab = new Tab({
      customer_id,
      customer_name: fallbackCustomerName,
      tabItems: updatedTabItems,
    });

    // Save the tab to the database
    const savedTab = await newTab.save();
    res.status(201).json(savedTab);
  } catch (err) {
    console.error("Error saving tab:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/tabs/:tabId", async (req: Request, res: Response) => {
  const { tabId } = req.params;

  try {
    const tab = await Tab.findOne({
      customer_id: new mongoose.Types.ObjectId(tabId),
    });

    if (!tab) {
      return res.status(404).json({ message: "Tab not found" });
    }

    return res.status(200).json(tab);
  } catch (error) {
    console.error("Error fetching tab:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/products/:barcode", async (req: Request, res: Response) => {
  const barcode = req.params.barcode;

  try {
    const product = await Product.findOne({ barcode: barcode }).exec();

    if (product) {
      res.json({ product });
    } else {
      res.status(404).json({ message: "Product not found" });
    }
  } catch (error) {
    console.error("Error fetching product by barcode:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/products/:barcode", async (req: Request, res: Response) => {
  const barcode = req.params.barcode;

  // Check if the user is authenticated
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      message: "Unauthorized: Please log in to add items to your tab.",
    });
  }

  // Get the current user's ID
  const userId = (req.user as userInterface)?.id || null;

  if (!userId) {
    return res.status(500).json({ message: "Could not retrieve user ID." });
  }

  try {
    // ... rest of the function implementation ...
  } catch (error) {
    console.error("Error adding product to tab:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post(
  "/api/login",
  [
    body("username").notEmpty().withMessage("Username is required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate(
      "local",
      { session: false },
      async (err: Error, user: userInterface, info: any) => {
        if (err) return next(err);
        if (!user) {
          return res.status(401).json({ error: "Invalid credentials" });
        }

        // Fetch the user's companyId from the database if not already present
        let companyId = user.companyId;
        if (!companyId) {
          const dbUser = await User.findById(user.id).exec();
          companyId = (dbUser as any)?.companyId;
        }

        // ✅ Add companyId to the payload
        const payload = {
          id: user.id,
          username: user.username,
          isAdmin: user.isAdmin,
          companyId: companyId, // Add this line
        };

        const token = jwt.sign(
          payload,
          process.env.JWT_SECRET || "your_jwt_secret",
          {
            expiresIn: "1h",
          }
        );

        // ✅ Send token back to client
        return res.status(200).json({
          message: "Login successful",
          token,
        });
      }
    )(req, res, next);
  }
);
app.get(
  "/api/products",
  passport.authenticate("jwt", { session: false }),
  async (req: Request, res: Response) => {
    const user = req.user as userInterface;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;

    try {
      const [products, total] = await Promise.all([
        Product.find({ companyId: user.companyId })
          .skip(skip)
          .limit(limit)
          .exec(),
        Product.countDocuments({ companyId: user.companyId }),
      ]);

      res.json({
        products,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
    } catch (err) {
      res.status(500).send(err);
    }
  }
);

app.get(
  "/api/products/category/:categoryId",
  async (req: Request, res: Response) => {
    const categoryId = req.params.categoryId;
    try {
      const products = await Product.find({ categoryId: categoryId }).exec();
      if (products.length > 0) {
        res.json(products);
      } else {
        res.status(404).json({ message: "No products found in this category" });
      }
    } catch (error) {
      console.error("Error fetching products by category:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);
app.get(
  "/api/products/:id",
  passport.authenticate("jwt", { session: false }),
  async (req: Request, res: Response) => {
    const companyName = req.query.companyName as string;
    const id = req.params.id;

    if (!companyName) {
      return res
        .status(400)
        .json({ message: "companyName query parameter is required" });
    }

    try {
      const company = await Company.findOne({ name: companyName });
      if (!company) {
        return res.status(404).json({ message: "Company not found" });
      }

      const product = await Product.findOne({
        _id: id,
        companyId: company._id,
      });
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }

      res.json(product);
    } catch (error) {
      console.error("Error fetching product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.put(
  "/api/products/:id",
  [
    body("productName").notEmpty().withMessage("Product name is required"),
    body("productPrice")
      .isNumeric()
      .withMessage("Product price must be a number"),
    body("productImage").notEmpty().withMessage("Product image is required"),
    body("productDescription")
      .optional()
      .isString()
      .withMessage("Product description must be a string"),
  ],
  passport.authenticate("jwt", { session: false }),
  async (req: Request, res: Response) => {
    const id = req.params.id;
    const updatedData = req.body;
    const user = req.user as userInterface; // Make sure user.companyId is available

    try {
      const product = await Product.findById(id).exec();
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }

      // Restrict by company
      if (product.companyId.toString() !== user.companyId.toString()) {
        return res.status(403).json({ message: "Forbidden: Not your company" });
      }

      const updatedProduct = await Product.findByIdAndUpdate(id, updatedData, {
        new: true,
      }).exec();
      res.json(updatedProduct);
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/api/products/:id",
  passport.authenticate("jwt", { session: false }),
  async (req: Request, res: Response) => {
    const id = req.params.id;
    const user = req.user as userInterface; // Make sure user.companyId is available

    try {
      const product = await Product.findById(id).exec();
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }

      // Restrict by company
      if (product.companyId.toString() !== user.companyId.toString()) {
        return res.status(403).json({ message: "Forbidden: Not your company" });
      }

      await Product.findByIdAndDelete(id).exec();
      res.json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);
app.get(
  "/api/company/products",
  passport.authenticate("jwt", { session: false }),
  async (req: Request, res: Response) => {
    const user = req.user as userInterface;
    try {
      const products = await Product.find({ companyId: user.companyId }).exec();
      res.json(products);
    } catch (err) {
      res.status(500).send(err);
    }
  }
);
app.post("/api/feedback", async (req: Request, res: Response) => {
  try {
    const report = new Report(req.body);
    await report.save();
    res.sendStatus(200); // Use sendStatus to send a proper HTTP status code
  } catch (error) {
    // Correctly place the catch block
    console.error("Error saving feedback:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put(
  "/api/users/adminAccess",
  adminOnly,
  async (req: Request, res: Response) => {
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

      return res
        .status(200)
        .json({ message: "User granted admin access", user });
    } catch (error) {
      console.error("Error updating admin access:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

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
      return res
        .status(200)
        .json({ isAdmin: true, message: "User has admin access" });
    } else {
      return res
        .status(200)
        .json({ isAdmin: false, message: "User does not have admin access" });
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
      return res
        .status(400)
        .json({ message: "Email and password are required." });
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

    return res
      .status(200)
      .json({ message: "Password has been reset successfully." });
  } catch (err) {
    console.error("Error during password reset request:", err);
    return res.status(500).json({ message: "Error on the server." });
  }
});

app.get("/api/user/:username", async (req: Request, res: Response) => {
  const { username } = req.params;

  try {
    const user = await User.find({ username: username }).exec();
    if (!user || user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/session", (req, res) => {
  if (req.session && req.session.user) {
    res.json({ username: req.session.user.username });
  } else {
    res.status(401).json({ message: "Not logged in" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
