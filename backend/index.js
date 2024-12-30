import express from "express";
import mysql from "mysql";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";

const app = express();
const secretKey = "your-secret-key"; // Replace with a strong secret key

// Database Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "marketplace",
});

app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",  // Adjust according to your frontend's URL
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Middleware to authenticate the user via JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "No token provided" });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: "Token is not valid" });
    req.user = user; // Attach user info to the request object
    next();
  });
};



// Home Route
app.get("/", (req, res) => {
  res.json("Welcome to the API");
});

// ---------------------- USER ROUTES ----------------------

// Register User
app.post(
  "/users/register",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    body("name").notEmpty().withMessage("Name is required"),
    body("address").notEmpty().withMessage("Address is required"),
    body("phoneNumber").notEmpty().withMessage("Phone Number is required")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error("Validation errors: ", errors.array());  // Log validation errors
      return res.status(400).json({ errors: errors.array() }); // Send detailed validation errors
    }

    const { name, email, password, address, phoneNumber, role } = req.body;

    console.log("Received registration data: ", req.body); // Log the data received from the frontend

    try {
      const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
      const query = "INSERT INTO users (name, email, password, address, phoneNumber, role) VALUES (?)";
      const values = [name, email, hashedPassword, address, phoneNumber, role || "Customer"];

      db.query(query, [values], (err, result) => {
        if (err) {
          console.error("Database query error: ", err);  // Log any query errors
          return res.status(500).json({ message: "Error registering user", error: err });
        }
        console.log("User registered successfully: ", result); // Log successful registration
        res.json({ message: "User registered successfully!" });
      });
    } catch (err) {
      console.error("Error in password hashing: ", err);  // Log error in hashing password
      res.status(500).json({ message: "Error processing registration", error: err });
    }
  }
);

// User Login
app.post("/users/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, data) => {
      if (err) return res.status(500).json(err);
      if (data.length === 0) return res.status(404).json({ message: "User not found" });

      const user = data[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) return res.status(401).json({ message: "Invalid password" });

      // Include role in token and response
      const token = jwt.sign({ userID: user.userID, role: user.role }, secretKey);
      res.json({ token, role: user.role, message: "Login successful" });
    });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Get User Profile based on Token
app.get("/users/me", authenticateToken, (req, res) => {
  const { userID } = req.user; // Get the userID from the decoded JWT token
  const query = "SELECT * FROM users WHERE userID = ?";
  
  db.query(query, [userID], (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length === 0) return res.status(404).json({ message: "User not found" });
    res.json(data[0]); // Return the user's data
  });
});

// Update User Info
app.put("/users/:id", (req, res) => {
  const { id } = req.params;
  const { name, address, phoneNumber, role } = req.body;

  const query = "UPDATE users SET name = ?, address = ?, phoneNumber = ?, role = ? WHERE userID = ?";
  const values = [name, address, phoneNumber, role, id];

  db.query(query, values, (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "User updated successfully!" });
  });
});

// Delete User
app.delete("/users/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM users WHERE userID = ?";
  db.query(query, [id], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "User deleted successfully!" });
  });
});

// ---------------------- PRODUCT ROUTES ----------------------

// Middleware for Role-Based Access Control
const authorize = (roles) => (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Authorization token required" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    if (!roles.includes(decoded.role)) return res.status(403).json({ message: "Access forbidden" });
    next();
  });
};

// Get All Products
app.get("/products", (req, res) => {
  const query = "SELECT * FROM products";
  db.query(query, (err, data) => {
    if (err) return res.status(500).json(err);
    res.json(data);
  });
});

// Get Single Product
app.get("/products/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT * FROM products WHERE id = ?";
  db.query(query, [id], (err, data) => {
    if (err) return res.status(500).json(err);
    res.json(data[0]);
  });
});

// Add a Product (Admin Only)
app.post("/products", (req, res) => {
  const { title, description, price, quantity, category, images } = req.body;
  const query =
    "INSERT INTO products (`title`, `description`, `price`, `quantity`, `category`, `images`) VALUES (?)";
  const values = [title, description, price, quantity, category, JSON.stringify(images)];
  db.query(query, [values], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Product added successfully!" });
  });
});

// Update Product (Admin Only)
app.put("/products/:id", (req, res) => {
  const { id } = req.params;
  const { title, description, price, quantity, category, images } = req.body;
  const query =
    "UPDATE products SET `title` = ?, `description` = ?, `price` = ?, `quantity` = ?, `category` = ?, `images` = ? WHERE id = ?";
  const values = [title, description, price, quantity, category, JSON.stringify(images)];
  db.query(query, [...values, id], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Product updated successfully!" });
  });
});

// Delete Product (Admin Only)
app.delete("/products/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM products WHERE id = ?";
  db.query(query, [id], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Product deleted successfully!" });
  });
});

// Notify Admin of Low Stock
app.get("/products/low-stock", authorize(["Admin"]), (req, res) => {
  const query = "SELECT * FROM products WHERE quantity < 5";
  db.query(query, (err, data) => {
    if (err) return res.status(500).json(err);
    res.json(data);
  });
});
// ---------------------- ORDER ROUTES ----------------------

// Place a New Order
app.post("/orders", authenticateToken, (req, res) => {
  const { items, totalAmount, shippingAddress } = req.body;
  const userID = req.user.userID; // Retrieved from token
  const orderDate = new Date().toISOString(); // Current date-time
  const status = "Pending";

  // Insert order into the database
  const query =
    "INSERT INTO orders (userID, orderDate, status, items, totalAmount, shippingAddress) VALUES (?)";
  const values = [userID, orderDate, status, JSON.stringify(items), totalAmount, shippingAddress];

  db.query(query, [values], (err, result) => {
    if (err) {
      console.error("Error placing order:", err);
      return res.status(500).json({ message: "Error placing order", error: err });
    }
    res.json({ message: "Order placed successfully!", orderID: result.insertId });
  });
});

// Get All Orders (Admin or User Specific)
app.get("/orders", authenticateToken, (req, res) => {
  const userID = req.user.userID;
  const role = req.user.role;

  let query = "SELECT * FROM orders";
  const queryParams = [];

  if (role !== "Admin") {
    query += " WHERE userID = ?";
    queryParams.push(userID);
  }

  db.query(query, queryParams, (err, data) => {
    if (err) {
      console.error("Error fetching orders:", err);
      return res.status(500).json(err);
    }
    res.json(data);
  });
});

// Get Single Order by ID
app.get("/orders/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const userID = req.user.userID;
  const role = req.user.role;

  const query = role === "Admin"
    ? "SELECT * FROM orders WHERE orderID = ?"
    : "SELECT * FROM orders WHERE orderID = ? AND userID = ?";
  const queryParams = role === "Admin" ? [id] : [id, userID];

  db.query(query, queryParams, (err, data) => {
    if (err) {
      console.error("Error fetching order:", err);
      return res.status(500).json(err);
    }
    if (data.length === 0) return res.status(404).json({ message: "Order not found" });
    res.json(data[0]);
  });
});

// Update Order Status (Admin Only)
app.put("/orders/:id", authorize(["Admin"]), (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  const query = "UPDATE orders SET status = ? WHERE orderID = ?";
  db.query(query, [status, id], (err) => {
    if (err) {
      console.error("Error updating order status:", err);
      return res.status(500).json(err);
    }
    res.json({ message: "Order status updated successfully!" });
  });
});

// Delete Order (Admin Only)
app.delete("/orders/:id", authorize(["Admin"]), (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM orders WHERE orderID = ?";
  db.query(query, [id], (err) => {
    if (err) {
      console.error("Error deleting order:", err);
      return res.status(500).json(err);
    }
    res.json({ message: "Order deleted successfully!" });
  });
});

// Add item to cart
app.post("/cart",authenticateToken, (req, res) => {
  const { productID, quantity } = req.body;
  const userID = req.user.userID;

  const query = `
    INSERT INTO cart (userID, productID, quantity)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE
    quantity = quantity + VALUES(quantity)
  `;

  db.query(query, [userID, productID, quantity], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Item added to cart successfully!" });
  });
});

// Get user's cart items
app.get("/cart", (req, res) => {
  const userID = req.user.userID;

  const query = `
    SELECT c.cartID, p.title, p.price, c.quantity
    FROM cart c
    JOIN products p ON c.productID = p.id
    WHERE c.userID = ?
  `;

  db.query(query, [userID], (err, data) => {
    if (err) return res.status(500).json(err);
    res.json(data);
  });
});

// Update cart item quantity
app.put("/cart", (req, res) => {
  const { productID, quantity } = req.body;
  const userID = req.user.userID;

  const query = `
    UPDATE cart
    SET quantity = ?
    WHERE userID = ? AND productID = ?
  `;

  db.query(query, [quantity, userID, productID], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Cart updated successfully!" });
  });
});

app.patch("/cart/:id", (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;

  const query = "UPDATE cart SET quantity = ? WHERE cartID = ?";
  db.query(query, [quantity, id], (err) => {
    if (err) return res.status(500).json({ message: "Error updating quantity", error: err });
    res.json({ message: "Quantity updated successfully!" });
  });
});

// Remove item from cart
app.delete("/cart/:productID", (req, res) => {
  const { productID } = req.params;
  const userID = req.user.userID;

  const query = `
    DELETE FROM cart
    WHERE userID = ? AND productID = ?
  `;

  db.query(query, [userID, productID], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Item removed from cart successfully!" });
  });
});
// Add item to wishlist
app.post("/wishlist", authenticateToken, (req, res) => {
  const { productID } = req.body;
  const userID = req.user.userID;

  const query = `
    INSERT IGNORE INTO wishlist (userID, productID)
    VALUES (?, ?)
  `;

  db.query(query, [userID, productID], (err) => {
    if (err) return res.status(500).json({ message: "Error adding to wishlist", error: err });
    res.json({ message: "Item added to wishlist successfully!" });
  });
});

// Get user's wishlist items
app.get("/wishlist", authenticateToken, (req, res) => {
  const userID = req.user.userID;

  const query = `
    SELECT w.wishlistID, p.title, p.price
    FROM wishlist w
    JOIN products p ON w.productID = p.id
    WHERE w.userID = ?
  `;

  db.query(query, [userID], (err, data) => {
    if (err) return res.status(500).json({ message: "Error fetching wishlist", error: err });
    res.json(data);
  });
});

// Remove item from wishlist
app.delete("/wishlist/:productID", authenticateToken, (req, res) => {
  const { productID } = req.params;
  const userID = req.user.userID;

  const query = `
    DELETE FROM wishlist
    WHERE userID = ? AND productID = ?
  `;

  db.query(query, [userID, productID], (err) => {
    if (err) return res.status(500).json({ message: "Error removing from wishlist", error: err });
    res.json({ message: "Item removed from wishlist successfully!" });
  });
});

// Start the Server
app.listen(8800, () => {
  console.log("Connected to backend on port 8800");
});
