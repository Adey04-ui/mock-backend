import asyncHandler from 'express-async-handler'
import User from '../models/userModel.js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// ---------- TOKEN GENERATORS ----------
const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' })
}

const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' })
}

// ---------- COOKIE OPTIONS ----------
const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000
}

const accessCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: 15 * 60 * 1000
}

// ---------- REGISTER ----------
const register = asyncHandler(async (req, res) => {
  const { name, email, phone, password } = req.body

  if (!name || !email || !phone || !password) {
    res.status(400)
    throw new Error("Please fill all fields")
  }

  const emailExists = await User.findOne({ email })
  const phoneExists = await User.findOne({ phone })

  if (emailExists) {
    res.status(400)
    throw new Error("Email already exists")
  }
  if (phoneExists) {
    res.status(400)
    throw new Error("Phone number already exists")
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  const profilePic =
    req.file?.path ||
    "https://res.cloudinary.com/dv2vh9w5o/image/upload/v1762165292/exc5prniqk1rpenkqqto.png"

  const user = await User.create({
    name,
    email,
    phone,
    password: hashedPassword,
    profilePic
  })

  const accessToken = generateAccessToken(user._id)
  const refreshToken = generateRefreshToken(user._id)

  user.refreshToken = refreshToken
  await user.save()

  // Cookie (only web apps)
  res.cookie("refreshToken", refreshToken, refreshCookieOptions)
  res.cookie("accessToken", accessToken, accessCookieOptions)

  res.status(201).json({
    _id: user._id,
    name: user.name,
    email: user.email,
    profilePic: user.profilePic,
    accessToken,
    refreshToken
  })
})

// ---------- LOGIN ----------
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    res.status(400)
    throw new Error("Please provide email and password")
  }

  const user = await User.findOne({ email })
  if (!user) {
    res.status(400)
    throw new Error("Email does not exist")
  }

  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
    res.status(400)
    throw new Error("Invalid password")
  }

  const accessToken = generateAccessToken(user._id)
  const refreshToken = generateRefreshToken(user._id)

  user.refreshToken = refreshToken
  await user.save()

  res.cookie("refreshToken", refreshToken, refreshCookieOptions)
  res.cookie("accessToken", accessToken, accessCookieOptions)

  res.json({
    _id: user._id,
    name: user.name,
    email: user.email,
    profilePic: user.profilePic,
    accessToken,
    refreshToken
  })
})

// ---------- REFRESH TOKEN ----------
const refresh = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    console.log("[REFRESH BACKEND] Decoded:", decoded); // should log { id: "6995a64be..." }
  } catch (err) {
    console.log("[REFRESH BACKEND ERROR]", err.message);
    return res.status(403).json({ message: "Invalid or expired refresh token" });
  }

  const user = await User.findById(decoded.id);
  if (!user) {
    return res.status(403).json({ message: "User not found" });
  }

  const newAccessToken = generateAccessToken(user._id.toString()); // ensure string
  const newRefreshToken = generateRefreshToken(user._id.toString());

  user.refreshToken = newRefreshToken;
  await user.save();

  console.log("[REFRESH BACKEND] New accessToken length:", newAccessToken.length);

  // For web: cookies
  res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);
  res.cookie("accessToken", newAccessToken, accessCookieOptions);

  // For mobile: JSON response
  res.json({
    accessToken: newAccessToken,     // ← this MUST be the JWT string
    refreshToken: newRefreshToken,
    user: {                          // optional safety
      _id: user._id,
      name: user.name,
      email: user.email,
      profilePic: user.profilePic
    }
  });
});

// ---------- GET ME ----------
const getMe = asyncHandler(async (req, res) => {
  res.json({
    _id: req.user._id,
    name: req.user.name,
    email: req.user.email,
    profilePic: req.user.profilePic
  })
})

// ---------- GET ALL ----------
const getAll = asyncHandler(async (req, res) => {
  const users = await User.find({}).select("-password -refreshToken")
  res.json(users)
})

// ---------- LOGOUT ----------
const logout = asyncHandler(async (req, res) => {
  const refreshToken = req.body.refreshToken

  res.cookie("accessToken", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true
  })
  res.cookie("refreshToken", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true
  })

  if (refreshToken) {
    await User.findOneAndUpdate(
      { refreshToken },
      { refreshToken: null }
    )
  }

  res.json({ message: "Logged out successfully" })
})

export { register, login, refresh, getMe, getAll, logout }
