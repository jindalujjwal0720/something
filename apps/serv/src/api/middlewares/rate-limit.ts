import rateLimit from 'express-rate-limit';
import { TooManyRequestsError } from '../../utils/errors';

export const emailRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  handler: () => {
    throw new TooManyRequestsError(
      'You have exceeded maximum number of requests. Please try again after some time',
    );
  },
});

export const rateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  handler: () => {
    throw new TooManyRequestsError(
      'You have exceeded maximum number of requests. Please try again after some time',
    );
  },
});
