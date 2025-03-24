import express from 'express';
const router = express.Router();

router.get('/', (req, res) => {
  res.send('Hello from the API');
});

// Import the user routes
import userRoutes from './routes/users';
router.use('/users', userRoutes);

export default router;
