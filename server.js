import express, { urlencoded } from 'express'
import dotenv from 'dotenv'
import cors from 'cors'
import {createServer} from 'http'
import { Server } from 'socket.io'
import { errorHandler } from './middleware/errorHandler.js'
import users from './routes/userRoutes.js'
import connectDB from './config/db.js'
import chatRoutes from './routes/chatRoutes.js'
import messages from './routes/messageRoute.js'
import User from './models/userModel.js'
import socketHandler from './socket/socketHandler.js'
import cookieParser from "cookie-parser"

dotenv.config()
const port = process.env.PORT 

connectDB()

const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: false}))

app.use(cookieParser())

app.use(cors({
  origin: ["http://localhost:5173",
            "http://localhost:8081",
            "https://whatsapp-three-topaz.vercel.app",
            "https://whatsapp-git-main-kennys-projects-2ff6d28e.vercel.app",
            "https://whatsapp-1t2ryp2tz-kennys-projects-2ff6d28e.vercel.app"], 
  credentials: true  
}))

const server = createServer(app)

const io = new Server(server, {
  cors: {
    origin: ["http://localhost:5173",
            "http://localhost:8081",
            "https://whatsapp-three-topaz.vercel.app",
            "https://whatsapp-git-main-kennys-projects-2ff6d28e.vercel.app",
            "https://whatsapp-1t2ryp2tz-kennys-projects-2ff6d28e.vercel.app"], // match your Vite app URL
    methods: ["GET", "POST"],
    credentials: true,
  },
})
app.set("io", io)

app.use('/api/users', users)
app.use('/api/chats', chatRoutes)
app.use('/api/messages', messages)
app.use(errorHandler)

socketHandler(io)

server.listen(port, ()=> console.log(`server started on port ${port}`))
