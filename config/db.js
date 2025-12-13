import mongoose from 'mongoose'

const connectDB = async (req, res) => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI)
    const date = Date.now()
    console.log(`MongoDB connected ${new Date(date).toLocaleTimeString('en-GB', 
      {
        hour: '2-digit',
        minute: '2-digit',
      })
    }`)
  } catch (error) {
    console.log(error)
    process.exit(1)
  }
}
export default connectDB