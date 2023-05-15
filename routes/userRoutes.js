import express from 'express'
const router  = express.Router()
import UserController from '../controllers/userController.js'
import checkAuthentication from '../middleware/authMiddleware.js'

//Route Middleware
router.use('/changepassword',checkAuthentication)
router.use('/loggeduser',checkAuthentication)

// Public Routes
router.post('/register',UserController.userRegistration)
router.post('/login',UserController.userLogin)
router.post('/reset-password-by-using-email',UserController.resetPasswordByUsingEmail)
router.post('/user-password-reset/:id/:jwtToken',UserController.userPasswordReset)

//Protected Routes
router.post('/changepassword',UserController.changeUserPassword)
router.get('/loggeduser',UserController.loggedUser)

export default router