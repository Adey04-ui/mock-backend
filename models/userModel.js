import mongoose from 'mongoose'
const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'please add a name'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'please add an email'],
      unique: true,
      trim: true,
      lowercase: true,
    },
    phone: {
      type: String,
      required: [true, 'please add a phone number'],
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, 'please input a password'],
      unique: true,
    },
    profilePic: {
      type: String,
      default: '',
    },
    lastSeen: {
      type: Date,
      default: Date.now
    },
    isOnline: {
      type: Boolean,
      default: false
    },
    refreshToken: {
      type: String,
    }
  },
  {
    timestamps: true
  }
)

export default mongoose.model('User', userSchema)