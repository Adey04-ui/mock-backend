import Chat from "../models/chatModel.js"

export const accessChat = async (req, res) => {
  try {
    const { userId } = req.body
    const loggedInUser = req.user._id

    if (!userId) {
      return res.status(400).json({ message: "No user to create from" })
    }

    // Check if chat already exists
    let chat = await Chat.findOne({
      users: { $all: [loggedInUser, userId] },
    })
      .populate("users", "-password")
      .populate("latestMessage")

    if (chat) {
      return res.status(200).json(chat)
    }

    // Create a new chat
    const newChat = await Chat.create({
      users: [loggedInUser, userId],
      unread: [
        { user: loggedInUser, count: 0 },
        { user: userId, count: 0 },
      ],
    })

    const fullChat = await Chat.findById(newChat._id)
      .populate("users", "-password")

    //  Emit to both users in real time
    const io = req.app.get("io")
    if (io && fullChat && fullChat.users) {
      fullChat.users.forEach((user) => {
        const roomId = user._id?.toString()
        io.to(roomId).emit("chatCreated", fullChat)
      })
    }

    return res.status(201).json(fullChat)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
}

//  Get all chats for logged-in user
export const getChats = async (req, res) => {
  try {
    const chats = await Chat.find({ users: { $in: [req.user?._id] } })
      .populate("users", "-password")
      .populate("latestMessage")
      .sort({ updatedAt: -1 })

    res.status(200).json(chats)
  } catch (error) {
    console.error(error)
    res.status(400).json({ message: error.message })
  }
}


// Get unread count for a chat
export const getUnreadCounts = async (req, res) => {
  try {
    const chats = await Chat.find({ "unread.user": req.user._id })
      .select("unread users latestMessageAt")
      .populate("users", "name email")

    const counts = chats.map((chat) => {
      const userUnread = chat.unread.find(
        (u) => u.user.toString() === req.user._id.toString()
      )
      return {
        user: req.user._id,
        chatId: chat._id,
        count: userUnread ? userUnread.count : 0,
      }
    })

    res.json(counts)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: "Failed to get unread counts" })
  }
}
