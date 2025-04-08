import * as express from 'express';
import { errorLogger } from './logger';

export type StatusCode = 400 | 401 | 403 | 404 | 409 | 429 | 500;

export const CommonErrors = {
  BadRequest: { name: 'Bad request', statusCode: 400 },
  Unauthorized: { name: 'Unauthorized', statusCode: 401 },
  Forbidden: { name: 'Forbidden', statusCode: 403 },
  NotFound: { name: 'Not found', statusCode: 404 },
  Conflict: { name: 'Conflict', statusCode: 409 },
  TooManyRequests: { name: 'Too many requests', statusCode: 429 },
  InternalServerError: { name: 'Internal server error', statusCode: 500 },
} as const;

export class AppError extends Error {
  public readonly name: string;
  public readonly statusCode: StatusCode;
  public readonly isOperational: boolean; // Indicates if the error is operational, i.e. can be handled

  constructor(
    name: string,
    statusCode: StatusCode,
    message: string,
    isOperational = true,
  ) {
    super(message);

    this.name = name;
    this.statusCode = statusCode || 500;
    this.isOperational = isOperational;

    Error.captureStackTrace(this);
  }
}

export class BadRequestError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.BadRequest.name,
      CommonErrors.BadRequest.statusCode,
      message,
    );
  }
}

export class UnauthorizedError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.Unauthorized.name,
      CommonErrors.Unauthorized.statusCode,
      message,
    );
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.Forbidden.name,
      CommonErrors.Forbidden.statusCode,
      message,
    );
  }
}

export class NotFoundError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.NotFound.name,
      CommonErrors.NotFound.statusCode,
      message,
    );
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.Conflict.name,
      CommonErrors.Conflict.statusCode,
      message,
    );
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message: string) {
    super(
      CommonErrors.TooManyRequests.name,
      CommonErrors.TooManyRequests.statusCode,
      message,
    );
  }
}

export class InternalServerError extends AppError {
  constructor(message: string, isOperational = true) {
    super(
      CommonErrors.InternalServerError.name,
      CommonErrors.InternalServerError.statusCode,
      message,
      isOperational,
    );
  }
}

class ErrorHandler {
  private sendErrorResponse(err: Error, res: express.Response): void {
    if (err instanceof AppError) {
      res.status(err.statusCode).json({
        error: {
          name: err.name,
          status: err.statusCode,
          message: err.message,
        },
      });
    } else {
      res.status(500).json({
        error: {
          name: err.name || 'Internal server error',
          status: 500,
          message: err.message || 'Something went wrong',
        },
      });
    }
  }

  public async handleError(
    error: Error,
    res: express.Response | null,
  ): Promise<void> {
    errorLogger.error(error.message, { stack: error.stack });
    if (res !== null) this.sendErrorResponse(error, res);
  }

  public isTrustedError(error: Error): boolean {
    if (error instanceof AppError) {
      return error.isOperational;
    }

    return false;
  }
}

export const handler = new ErrorHandler();
