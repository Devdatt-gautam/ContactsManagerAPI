const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
// Register a user
// post /api/user/register
//access public
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    res.status(400);
    throw new Error("All fields are necessary");
  }
  const unavailableUser = await User.findOne({ email });
  if (unavailableUser) {
    res.status(400);
    throw new Error("User already exists");
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log(`hashed password is ${hashedPassword}`);
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });
  if (user) {
    console.log("user created");
    res.status(201).json({ id: user.id, email: user.email });
  } else {
    res.status(400);
    throw new Error("User data is not valid");
  }
});
// login user
// post /api/user/login
//access public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400);
    throw new Error("All fields are mandatory");
  }
  const user = await User.findOne({ email });

  //compare passwords and hashed passwords
  if (user && (await bcrypt.compare(password, user.password))) {
    const accessToken = jwt.sign(
      {
        user: {
          username: user.username,
          email: user.email,
          id: user.id,
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );
    res.status(200).json({ accessToken });
  } else {
    console.log(4);
    res.status(401);
    throw new Error("Invalid email or password");
  }
});
// login user
// post /api/user/login
//access private
const currentUser = asyncHandler((req, res) => {
  res.json(req.user);
});

module.exports = { registerUser, loginUser, currentUser };
