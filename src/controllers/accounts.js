const { ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const { connectToDatabase } = require("../utils/db");

const {
  validateEmail,
  validatePassword,
  encryptData,
  createToken,
  generateCsrfToken,
} = require("../utils");

const signupNewUser = async (req, res) => {
  try {
    const db = await connectToDatabase();
    const { email, password } = req.body;
    const csrfToken = generateCsrfToken();

    // Validate email first
    const emailValidation = validateEmail(email);
    if (emailValidation.error) {
      return res.status(400).json({ error: emailValidation.error });
    }

    // Validate password second
    const passwordValidation = validatePassword(password);
    if (passwordValidation.error) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    // Check if email is already in use
    const existingUser = await db.collection("accounts").findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email is taken!" });
    }

    // Encrypt password and continue with user creation logic
    const encryptedPassword = await encryptData("password", password);
    const result = await db.collection("accounts").insertOne({
      ...req.body,
      ...encryptedPassword,
    });

    const token = createToken(result.insertedId);
    await db
      .collection("accounts")
      .updateOne({ _id: new ObjectId(result.insertedId) }, { $set: { token } });

    res.cookie("AuthToken", token, {
      maxAge: 1000 * 60 * 60,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });
    res.cookie("CSRF-TOKEN", csrfToken, {
      maxAge: 1000 * 60 * 60,
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const signinUser = async (req, res) => {
  const csrfToken = generateCsrfToken();
  try {
    const db = await connectToDatabase();
    const { email, password } = req.body;

    // Validate email
    const emailValidation = validateEmail(email);
    if (emailValidation.error) {
      return res.status(400).json({ error: emailValidation.error });
    }

    // Validate password before proceeding with the database query
    const passwordValidation = validatePassword(password);
    if (passwordValidation.error) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    const existingUser = await db.collection("accounts").findOne({ email });
    if (existingUser) {
      // Comparing the password after validation
      const validity = await bcrypt.compare(password, existingUser.password);
      if (!validity) {
        return res.status(400).json({ error: "Wrong password" });
      }

      const { _id } = existingUser;
      const token = createToken(_id);
      await db
        .collection("accounts")
        .updateOne({ _id: new ObjectId(_id) }, { $set: { token } });

      res.cookie("AuthToken", token, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
      });

      res.cookie("CSRF-TOKEN", csrfToken, {
        maxAge: 1000 * 60 * 60,
        httpOnly: false,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Strict",
      });

      return res.status(200).json({ message: "User successfully signed in" });
    } else {
      return res.status(404).json({ error: "Email does not exist" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const fetchSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  console.log({ requestedUserId });
  if (!requestedUserId) {
    return res.status(400).json({ error: "Requested user ID is missing" });
  }

  try {
    const db = await connectToDatabase();
    const user = await db
      .collection("accounts")
      .findOne({ _id: new ObjectId(requestedUserId) });
    if (user) {
      res.status(200).json(user);
    } else {
      res
        .status(404)
        .json({ error: `Failed to fetch data with id: ${requestedUserId}` });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const deleteSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  try {
    const db = await connectToDatabase();
    const user = await db
      .collection("accounts")
      .findOneAndDelete({ _id: new ObjectId(requestedUserId) });
    if (user) {
      res.status(200).json({ message: "User successfully deleted" });
    } else {
      res.status(404).json({
        error: `Failed to delete user with with id:${requestedUserId}`,
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
const updateSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  try {
    const db = await connectToDatabase();
    const passwordToUpdateTo = req.body.password;
    const emailToUpdateTo = req.body.email;
    // If keys that needs to be validated are present, perform validation and encryption
    if (passwordToUpdateTo || emailToUpdateTo) {
      if (passwordToUpdateTo) {
        const passwordValidation = validatePassword(passwordToUpdateTo);
        if (passwordValidation.error) {
          return res.status(400).json({ error: passwordValidation.error });
        }
        //Encyrt the password
        const encryptedData = await encryptData("password", passwordToUpdateTo);
        if (encryptedData.error) {
          return res.status(500).json({ error: encryptedData.error });
        }
        req.body.password = encryptedData.password;
      }
      if (emailToUpdateTo) {
        const emailValidation = validateEmail(emailToUpdateTo);
        if (emailValidation.error) {
          return res.status(400).json({ error: emailValidation.error });
        }
      }
    }
    // Update the document
    const user = await db
      .collection("accounts")
      .findOneAndUpdate(
        { _id: new ObjectId(requestedUserId) },
        { $set: req.body }
      );

    if (user) {
      return res.status(200).json({ message: "User updated successfully" });
    } else {
      return res
        .status(404)
        .json({ error: `Failed to fetch data with id :${requestedUserId}` });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
const fetchAllUsers = async (req, res) => {
  try {
    const db = await connectToDatabase();
    const users = await db.collection("accounts").find({}).toArray(); // Convert cursor to array
    if (users.length > 0) {
      res.status(200).json(users);
    } else {
      res.status(404).json({ error: "No users found" });
    }
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: error.message });
  }
};

module.exports = {
  signupNewUser,
  fetchSingleUser,
  fetchAllUsers,
  deleteSingleUser,
  updateSingleUser,
  signinUser,
};
