import jwt from "jsonwebtoken"
import User from "../models/userModel.js"
import Message from "../models/messageModel.js"

// Keep track of online users (userId -> [socketIds])
const onlineUsers = new Map()

export default function socketHandler(io) {
  // ------------------- AUTH MIDDLEWARE -------------------
  io.use(async (socket, next) => {
    try {
      let token

      // ----------- 1. Mobile / RN (auth.token) -----------
      if (socket.handshake.auth?.token) {
        token = socket.handshake.auth.token
      }

      // ----------- 2. Web (accessToken cookie) -----------
      if (!token && socket.handshake.headers.cookie) {
        const match = socket.handshake.headers.cookie.match(
          /accessToken=([^;]+)/
        )
        if (match) token = match[1]
      }

      // ----------- 3. No token -----------
      if (!token) {
        console.log("auth skipped")
        return next()
      }

      // ----------- 4. Verify token -----------
      const decoded = jwt.verify(token, process.env.JWT_SECRET)

      const user = await User.findById(decoded.id).select(
        "_id name email"
      )

      if (!user) {
        return next(new Error("User no longer exists"))
      }

      socket.user = user
      next()
    } catch (err) {
      console.log("Socket auth error:", err.message)
      next(new Error("Not authorized"))
    }
  })

  // ------------------- MAIN CONNECTION -------------------
  io.on("connection", async (socket) => {
    console.log(" Socket connected:", socket.id)

    const user = socket.user

    // If authenticated user
    if (user?._id) {
      const userId = user._id.toString()
      const userSockets = onlineUsers.get(userId) || []
      onlineUsers.set(userId, [...userSockets, socket.id])

      // If first connection, mark online
      if (userSockets.length === 0) {
        await User.findByIdAndUpdate(userId, {
          isOnline: true,
          lastSeen: new Date(),
        })
        io.emit("userStatusChanged", { userId, isOnline: true })
      }
    }

    // ------------------- EMAIL CHECK -------------------
    socket.on("checkEmail", async (email) => {
      try {
        const exists = await User.findOne({ email })
        socket.emit("emailStatus", {
          available: !exists,
          message: exists ? "Email is taken" : "Email is available",
        })
      } catch (error) {
        console.error("Email check error:", error)
        socket.emit("emailStatus", {
          available: false,
          message: "Error checking email",
        })
      }
    })

    // ------------------- PHONE CHECK -------------------
    socket.on("checkPhone", async (phone) => {
      try {
        const exists = await User.findOne({ phone })
        socket.emit("phoneStatus", {
          available: !exists,
          message: exists ? "Phone number is taken" : "Phone number is available",
        })
      } catch (error) {
        console.error("Phone check error:", error)
        socket.emit("phoneStatus", {
          available: false,
          message: "Error checking phone number",
        })
      }
    })

    // ------------------- CHAT JOIN / SETUP -------------------
    socket.on("setup", (userId) => {
      if (!userId) return
      socket.join(userId.toString())
      console.log(` Socket ${socket.id} joined user room ${userId}`)
    })

    socket.on("joinChat", async (chatId) => {
      if (!socket.user) return

      const chat = await Chat.findById(chatId)
      if (!chat) return

      const isMember = chat.users.some(
        (u) => u.toString() === socket.user._id.toString()
      )

      if (!isMember) return

      socket.join(chatId.toString())
    })

    // ------------------- CHAT EVENTS -------------------
    socket.on("newChat", (chat) => {
      if (!chat?.users) return
      chat.users.forEach((u) => {
        io.to(u._id.toString()).emit("chatCreated", chat)
      })
    })

    socket.on("chatUpdated", (chat) => {
      if (!chat?.users) return
      chat.users.forEach((u) => {
        socket.to(u._id).emit("chatUpdated", chat)
      })
    })

    // ------------------- NEW MESSAGE -------------------
socket.on("newMessage", async (message) => {
  try {
    const chatId =
      message?.chatId?._id ||
      message?.chat?._id ||
      message?.chatId ||
      (message?.chat && message.chat._id)

    if (!chatId) {
      console.warn("newMessage missing chatId:", message)
      return
    }

    const senderId = socket.user._id.toString()

    // Save or update message in the database if needed
    let savedMessage
    if (!message._id || message._id.startsWith("temp-")) {
      savedMessage = await Message.create({
        chatId,
        sender: senderId,
        content: message.content,
        timestamp: new Date(),
        readBy: [],
        deliveredTo: [],
        status: "sent",
      })
      io.to(senderId).emit("messageStatusUpdate", {
        messageId: savedMessage._id,
        status: "sent",
      })
    } else {
      savedMessage = await Message.findById(message._id)
    }

    const chatUsers = message?.chat?.users || []

    // Emit to all recipients except the sender
    const deliveredTo = savedMessage.deliveredTo
    for (const u of chatUsers) {
      if (u._id.toString() !== senderId) {
        io.to(u._id.toString()).emit("messageReceived", savedMessage)
        deliveredTo.push(u._id.toString())
      }
    }
    // Update deliveredTo in DB & mark as delivered
    if (deliveredTo.length > 0) {
      savedMessage.deliveredTo = deliveredTo
      savedMessage.status = "delivered"
      await savedMessage.save()

      // Notify sender that message is delivered
      io.to(senderId).emit("messageDelivered", {
        messageId: savedMessage._id,
        deliveredTo,
      })
    }

    // Also emit to the chat room (if multiple devices)
    socket.to(chatId.toString()).emit("messageReceived", savedMessage)

  } catch (err) {
    console.error("Error in newMessage handler:", err)
  }
})

// ------------------- MARK MESSAGE READ -------------------
    socket.on("messageRead", async ({ chatId, userId }) => {
      try {
        await Message.updateMany(
          {
            chatId,
            sender: { $ne: userId },
            readBy: { $ne: userId },
          },
          { 
            $addToSet: { readBy: userId },
            $set: { status: "read" }, 
          }
        )
        socket.to(chatId.toString()).emit("messagesRead", { chatId, userId })
      } catch (err) {
        console.error("messageRead socket error:", err)
      }
    })

    // ------------------- DISCONNECT -------------------
    socket.on("disconnect", async () => {
      console.log(" Socket disconnected:", socket.id)

      if (user?._id) {
        const userId = user._id.toString()
        const userSockets = onlineUsers.get(userId) || []

        const updatedSockets = userSockets.filter((id) => id !== socket.id)

        if (updatedSockets.length === 0) {
          // User is now fully offline
          onlineUsers.delete(userId)
          await User.findByIdAndUpdate(userId, {
            isOnline: false,
            lastSeen: new Date(),
          })
          io.emit("userStatusChanged", {
            userId,
            isOnline: false,
            lastSeen: new Date(),
          })
        } else {
          onlineUsers.set(userId, updatedSockets)
        }
      }
    })
  })
}
