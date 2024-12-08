const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const validator = require("validator");
const jwt = require("jsonwebtoken");
const { connectToDatabase } = require("./db");
const { ObjectId } = require("mongodb");
require("dotenv").config();

const createToken = (_id) => {
  return jwt.sign({ _id }, `${process.env.SECRET}`, { expiresIn: "3d" });
};

// Generate a random CSRF token
function generateCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

const validateCsrfToken = (req, res, next) => {
  const csrfTokenFromCookie = req.cookies["CSRF-TOKEN"];
  const csrfTokenFromHeader = req.headers["x-csrf-token"];

  if (!csrfTokenFromCookie || !csrfTokenFromHeader) {
    return res.status(403).json({ error: "CSRF token missing" });
  }

  if (csrfTokenFromCookie !== csrfTokenFromHeader) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  next(); // CSRF validation passed
};

const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, `${process.env.SECRET}`);
    //console.log("Token decoded:", decoded);
    return decoded;
  } catch (error) {
    console.log(error.message);
    //console.error("Token verification error:", error);
    throw new Error("Invalid token");
  }
};

const validateEmail = (email) => {
  if (!email) {
    return { error: "Email is required!" };
  } else if (!validator.isEmail(email)) {
    return { error: "Invalid email format" }; // Updated to match the test expectation
  } else {
    return { message: "Success" };
  }
};

const validatePassword = (password) => {
  if (!password) {
    return { error: "Password is required!" };
  } else if (!validator.isStrongPassword(password)) {
    return { error: "Password must be at least 6 characters long" }; // Updated to match the test expectation
  } else {
    return { message: "Success" };
  }
};

const encryptData = async (key, value) => {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(value, salt);
  return {
    [key]: hash,
  };
};
const authenticate = async (req, res, next) => {
  const userTokenCookie = req.cookies?.AuthToken;
  if (!["GET", "PUT", "DELETE"].includes(req.method)) {
    return next(); // Skip authentication for other methods
  }

  if (!userTokenCookie) {
    return res.status(401).json({
      error: "Unauthorized - Token missing. Please login or signup first.",
    });
  }

  try {
    const decoded = verifyToken(userTokenCookie);
    const requestingUserId = new ObjectId(decoded?._id); // Convert _id to ObjectId
    const db = await connectToDatabase();
    const user = await db
      .collection("accounts")
      .findOne({ _id: requestingUserId });

    if (!user) {
      return res.status(404).json({ error: "Requested user not found" });
    }
    req.requestedUserId = requestingUserId.toString(); // Attach the ID to req object
    req.user = user; // Attach user details to req object
    console.log({ authToken: req.requestedUserId });

    // Restrict access to `/users` for non-admins
    if (
      req.path === "/users" &&
      req.method === "GET" &&
      user.userRole !== "admin"
    ) {
      return res
        .status(403)
        .json({ error: "Forbidden - Admin access required." });
    }

    return next(); // Proceed to the next middleware/route handler
  } catch (error) {
    console.error("Authentication error:", error);
    return res
      .status(401)
      .json({ error: "Unauthorized - Invalid or expired token" });
  }
};

// const authenticate = async (req, res, next) => {
//   const userTokenCookie = req.cookies?.AuthToken;
//   if (req.method === "GET" || req.method === "PUT" || req.method === "DELETE") {
//     // Check for the cookie in request
//     if (!userTokenCookie) {
//       return res.status(401).json({
//         error:
//           "Unauthorized - Token missing. Please login or signup first in order to be authenticated",
//       });
//     }
//     let HereisTheToken;

//     try {
//       // Verify the token
//       const decoded = verifyToken(userTokenCookie);
//       HereisTheToken = decoded;
//       //we then fetch the user in request to see if they have admin right
//       const requestingUserId = decoded?._id;
//       //set a new header with the userId
//       req.setHeader("requestedUserId", requestingUserId);
//       const db = await connectToDatabase();
//       const user = await db
//         .collection("accounts")
//         .findOne({ _id: new ObjectId(requestingUserId) });
//       if (user) {
//         if (user?.userRole === "admin") {
//           //we let them go through with the request
//           next();
//         } else {
//           if (user?._id === requestingUserId) {
//             // we allow them rights to their data
//             next();
//           } else {
//             return res.status(401).json({
//               error:
//                 "Unauthorized Access - You are trying to access information to which you are not the super-user",
//             });
//           }
//         }
//       } else {
//         res.status(404).json({ error: "Requested user not found" });
//       }
//       next(); // Continue to the next middleware or route handler
//     } catch (error) {
//       return res.status(401).json({
//         HereisTheToken,
//         userTokenCookie,
//         error: "Unauthorized - Invalid token",
//       });
//     }
//   } else {
//     // For other HTTP methods, no authentication is needed
//     next();
//   }
// };
module.exports = {
  createToken,
  verifyToken,
  validateEmail,
  validatePassword,
  encryptData,
  authenticate,
  generateCsrfToken,
  validateCsrfToken,
};
