import express from 'express';
const router = express.Router();

router.get('/', (req, res) => {
  res.send('Hello from the API');
});

// Import the auth routes
import authRoutes from './routes/auth';
router.use('/auth', authRoutes);

// Import the user routes
import userRoutes from './routes/users';
router.use('/users', userRoutes);

export default router;
