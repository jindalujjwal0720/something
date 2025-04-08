import { Application, ErrorRequestHandler } from 'express';
import { AppError, CommonErrors, handler } from '../utils/errors';
import { isCelebrateError } from 'celebrate';

interface ErrorLoaderProps {
  app: Application;
}

export const errorLoader = async ({ app }: ErrorLoaderProps) => {
  // Catch 404 and forward to error handler
  app.all('*', (req, res, next) => {
    next(
      new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        `Can't ${req.method} ${req.originalUrl}, route not found`,
      ),
    );
  });

  // Error handling
  app.use(((err, req, res, _next) => {
    if (isCelebrateError(err)) {
      return handler.handleError(
        new AppError(
          CommonErrors.BadRequest.name,
          CommonErrors.BadRequest.statusCode,
          err.details.get('body')?.message || 'Something went wrong',
        ),
        res,
      );
    }

    handler.handleError(err, res);
  }) satisfies ErrorRequestHandler);
};
