import { rateLimiter } from '../../middlewares/rate-limit';

export const handler = rateLimiter;
