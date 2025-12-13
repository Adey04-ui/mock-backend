import mongoose from 'mongoose'

const chatSchema = mongoose.Schema({
  users: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],
  latestMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message',
  },
  latestMessageAt: {
    type: Date,
    default: Date.now
  },
  unread: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      count: { type: Number, default: 0 },
    },
  ],
})

export default mongoose.model('Chat', chatSchema)