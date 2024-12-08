const express = require("express");
const { authenticate, validateCsrfToken } = require("../utils/index.js");
const {
  signupNewUser,
  signinUser,
  updateSingleUser,
  fetchSingleUser,
  fetchAllUsers,
  deleteSingleUser,
} = require("../controllers/accounts.js");

const router = express.Router();

//Authentication Middleware being applied globally
router.use(authenticate); //disable when running tests

//creating new user
router.post("/signup", signupNewUser);

//logging in user
router.post("/signin", signinUser);

//updating user
router.put("/update", updateSingleUser);

//delete user
router.delete("/delete", deleteSingleUser);

//fetch single user
router.get("/user", fetchSingleUser);

//fetch all users
router.get("/users", fetchAllUsers);

module.exports = router;
