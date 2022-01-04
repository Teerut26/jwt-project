require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const User = require("./model/user");
const TokenExp = require("./model/tokenExp");
const auth = require("./middleware/auth");

const app = express();

app.use(cors());

app.use(express.json({ limit: "50mb" }));

app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(200).send({
        error: true,

        message: "All input is required",
      });
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(200).send({
        error: true,

        message: "User Already Exist. Please Login",
      });
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(200).send({
        error: true,

        message: "All input is required",
      });
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(200).send({
      error: true,
      message: "Invalid Credentials",
    });
  } catch (err) {
    console.log(err);
  }
});

app.get("/logout", async (req, res) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) {
    return res.status(200).send({
      error: true,
      message: "A token is required for authentication",
    });
  }

  const oldTokenExp = await TokenExp.findOne({ token });

  if (oldTokenExp) {
    return res.status(200).send({
      error: true,
      message: "Token is black listed.",
    });
  }

  await TokenExp.create({
    token,
  });

  res.status(200).send({
    error: false,
    message: "Add token expire to db success.",
  });
});

app.get("/welcome", auth, (req, res) => {
  res.status(200).send({
    success: true,
    message: "Welcome 🙌",
  });
});

app.get("/me", auth, async (req, res) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];
  const { user_id } = jwt.verify(token, process.env.TOKEN_KEY);
  const { level, _id, email } = await User.findOne({ _id: user_id });
  res.status(200).send({
    level,
    _id,
    email,
  });
});

// This should be the last route else any after it won't work
app.use("*", (req, res) => {
  res.status(404).json({
    error: true,
    message: "You reached a route that is not defined on this server",
  });
});

module.exports = app;
