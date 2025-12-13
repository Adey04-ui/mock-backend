import mongoose, { mongo } from 'mongoose'

const messageSchema = mongoose.Schema({
  chatId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chat',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  deliveredTo:  [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: []
  },],
  content: {
    type: String,
    required: true
  },
  readBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: [],
  },],
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ["sending", "sent", "delivered", "read", "failed"],
    default: "sent"
  },
})

export default mongoose.model('Message', messageSchema)