import express from "express"
import { sendMessage, getMessages, readMessages, getAllMessages } from "../controllers/messageController.js"
import { protect } from "../middleware/Auth.js"

const router = express.Router()

router.post('/', protect, sendMessage)

router.get('/:chatId', protect, getMessages)

router.put('/read/:chatId', protect, readMessages)

router.get('/all', protect, getAllMessages)

export default router