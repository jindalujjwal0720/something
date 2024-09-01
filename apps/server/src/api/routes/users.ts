import express from 'express';
import { UserController } from '../controllers/user';
import { RateLimiterMiddleware } from '../middlewares/rate-limit';
import { AuthMiddleware } from '../middlewares/authentication';

const router = express.Router();
const userController = new UserController();
const authMiddleware = new AuthMiddleware();
const rateLimiterMiddleware = new RateLimiterMiddleware();

router.get(
  '/me',
  rateLimiterMiddleware.limiter,
  authMiddleware.requireAuthenticated.bind(authMiddleware),
  userController.getMe.bind(userController),
);

export default router;
