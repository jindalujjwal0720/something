import * as e from 'express';
import { AppError, CommonErrors } from '../../utils/errors';
import { AuthService } from '../../services/auth';
import User from '../../models/user';

export class AuthMiddleware {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService(User);
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
      res.locals.user = payload;

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
    const { mfaVerified } = res.locals.user;

    const token = this.authService.generate2FAAccessToken(res.locals.user);

    if (!mfaVerified) {
      return res.status(CommonErrors.Unauthorized.statusCode).json({
        requires2FA: true,
        token,
      });
    }

    next();
  }
}
