import express from "express"
import { accessChat, getChats, getUnreadCounts } from "../controllers/chatController.js"
import { protect } from "../middleware/Auth.js"

const router = express.Router()

router.post('/', protect, accessChat)

router.get('/', protect, getChats)

router.get('/unread', protect, getUnreadCounts)

export default router