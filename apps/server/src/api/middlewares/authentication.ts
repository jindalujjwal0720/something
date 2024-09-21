import * as e from 'express';
import { AppError, CommonErrors } from '../../utils/errors';
import { AuthService } from '../../services/auth';
import User from '../../models/user';
import { publisher } from '../../events';

export class AuthMiddleware {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService(User, publisher);
  }

  public async requireAuthenticated(
    req: e.Request,
    res: e.Response,
    next: e.NextFunction,
  ) {
    try {
      const token = req.headers.authorization?.split(' ')[1];

      if (!token) {
        throw new AppError(
          CommonErrors.Unauthorized.name,
          CommonErrors.Unauthorized.statusCode,
          'Invalid access token',
        );
      }

      const payload = await this.authService.verifyAccessToken(token);
      req.user = payload;

      next();
    } catch (err) {
      next(err);
    }
  }

  public async requireMFAVerified(
    req: e.Request,
    res: e.Response,
    next: e.NextFunction,
  ) {
    const { mfaVerified } = req.user;

    const token = this.authService.generate2FAAccessToken(req.user);

    if (!mfaVerified) {
      return res.status(CommonErrors.Unauthorized.statusCode).json({
        requires2FA: true,
        token,
      });
    }

    next();
  }
}
