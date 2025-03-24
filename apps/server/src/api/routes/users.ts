import express from 'express';
import { UserController } from '../controllers/user';
import { rateLimiter } from '../middlewares/rate-limit';
import { requireAuthenticated } from '../middlewares/authentication';

const router = express.Router();
const userController = new UserController();

router.use(rateLimiter);
router.use(requireAuthenticated);

router.get('/me', userController.getMe.bind(userController));
router.patch('/me', userController.updateMe.bind(userController));

export default router;
