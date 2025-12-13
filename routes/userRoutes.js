import express from 'express'
import { register, login, getAll, getMe, logout, refresh } from '../controllers/userController.js'
import { protect } from '../middleware/Auth.js'
import upload from '../middleware/multer.js'

const router = express.Router()

router.post('/', upload.single("profilePic"), register)

router.post('/login', login)

router.post('/refresh', refresh) // reuse logout controller to clear cookies on refresh failure

router.get('/', getAll)

router.get('/me', protect, getMe)

router.post('/logout', protect, logout)

export default router