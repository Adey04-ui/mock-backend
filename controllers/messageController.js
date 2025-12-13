import Message from "../models/messageModel.js"
import Chat from "../models/chatModel.js"

export const sendMessage = async(req, res) => {
  try {
    const {chatId, recipient, content} = req.body
  
    if (!chatId || !content) {
      return res.status(400).json({ message: "chatId and content are required" })
    }
  
    const createMessage = await Message.create({
      chatId,
      sender: req.user._id,
      deliveredTo: recipient,
      content,
      unread: true
    })
  
    console.log('user', req.user?._id)
  
    const fullMessage = await Message.findById(createMessage._id)
        .populate("sender", "name email profilePic")
        .populate("deliveredTo", "name email")
        .populate({
          path: "chatId",
          populate: { path: "users", select: "name email" },
        })
  
    await Chat.findByIdAndUpdate(chatId, {
      latestMessage: createMessage._id,
      latestMessageAt: new Date()
    })

    await Chat.updateOne(
      { _id: chatId },
      {
        $inc: { "unread.$[elem].count": 1 },
      },
      {
        arrayFilters: [{ "elem.user": { $ne: req.user._id } }],
      }
    )
  
      const io = req.app.get("io")
      if (io && fullMessage.chatId?.users) {
        fullMessage.chatId.users.forEach((user) => {
          if (user._id.toString() === req.user._id.toString()) return
          io.to(user._id.toString()).emit("messageReceived", fullMessage)
        })
      }
  
    res.status(201).json(fullMessage)
  } catch (error) {
    console.log(error)
  }
}

export const getMessages = async(req, res) => {
  try {
    const page = parseInt(req.query.page) || 1
    const limit = parseInt(req.query.limit) || 20
    const skip = (page - 1) * limit

    const messages = await Message.find({ chatId: req.params.chatId })
      .sort({ timestamp: 1 })
      .skip(skip)
      .limit(limit)
      .populate("sender", "name email profilePic")
      .populate("deliveredTo", "name email")
      .lean()

    const total = await Message.countDocuments({ chatId: req.params.chatId })

    res.status(200).json({
      messages,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
}

export const readMessages = async(req, res) => {
  try {
    const { chatId } = req.params
    const userId = req.user._id
  
    await Message.updateMany(
      { chatId, sender: { $ne: userId }, readBy: { $ne: userId } },
      { 
        $addToSet: { readBy: userId },
        $set: {status: 'read'}
      }
    )

    await Chat.updateOne(
      { _id: chatId, "unread.user": req.user._id },
      { $set: { "unread.$.count": 0 } }
    )
  
    res.json({ message: 'success' })
  } catch (error) {
    console.error("readMessages Error:", error)
    res.status(500).json({ message: "Failed to mark messages as read" })
  }
}

export const getAllMessages = async (req, res) => {
  try {
    const messages = await Message.find()
      .populate("chatId", "users latestMessageAt")
      .populate("sender", "name email profilePic")
      .sort({ timestamp: -1 })

    res.status(200).json(messages)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: "Failed to fetch messages" })
  }
}