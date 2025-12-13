import asyncHandler from 'express-async-handler'
import User from '../models/userModel.js'
import jwt from 'jsonwebtoken'

const protect = asyncHandler(async (req, res, next) => {
  let token

  // ----------- 1. Mobile App (Bearer Token) -----------
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1]
  }

  // ----------- 2. Web App (accessToken Cookie) -----------
  if (!token && req.cookies?.accessToken) {
    token = req.cookies.accessToken
  }

  // ----------- 3. No token found -----------
  if (!token) {
    res.status(401)
    throw new Error("Not authorized, no token")
  }

  // ----------- 4. Verify Access Token -----------
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    req.user = await User.findById(decoded.id).select("-password -refreshToken")

    if (!req.user) {
      res.status(401)
      throw new Error("User no longer exists")
    }

    next()
  } catch (err) {
    console.log("Access token invalid:", err.message)
    res.status(401)
    throw new Error("Not authorized, invalid or expired token")
  }
})

export { protect }
