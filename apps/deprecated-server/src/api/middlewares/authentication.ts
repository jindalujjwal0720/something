import { RequestHandler } from 'express';
import { AppError, CommonErrors } from '../../utils/errors';
import { generate2FAAccessToken, verifyAccessToken } from '../../utils/auth';

export const requireAuthenticated: RequestHandler = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Invalid access token',
      );
    }

    const payload = await verifyAccessToken(token);
    res.locals.user = payload;

    next();
  } catch (err) {
    next(err);
  }
};

export const requireMFAVerified: RequestHandler = async (req, res, next) => {
  const { mfaVerified } = res.locals.user;

  const token = generate2FAAccessToken(res.locals.user);

  if (!mfaVerified) {
    return res.status(CommonErrors.Unauthorized.statusCode).json({
      requires2FA: true,
      token,
    });
  }

  next();
};
