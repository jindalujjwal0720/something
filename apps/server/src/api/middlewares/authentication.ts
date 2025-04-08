import { RequestHandler } from 'express';
import { auth } from '../../utils/auth';
import { UnauthorizedError } from '../../utils/errors';

export const requireAuthenticated: RequestHandler = async (req, res, next) => {
  try {
    const session = await auth.api.getSession({
      headers: new Headers(req.headers as Record<string, string>),
    });

    if (!session) {
      throw new UnauthorizedError('Unauthorized');
    }

    res.locals.session = session;
    next();
  } catch (error) {
    next(error);
  }
};
