import { RequestHandler } from 'express';
import { emailRateLimiter } from '../../middlewares/rate-limit';
import { BadRequestError, NotFoundError } from '../../../utils/errors';
import User from '../../../models/user';
import {
  excludeSensitiveFields,
  generateEmailVerificationToken,
  generatePayload,
} from '../../../utils/auth';
import { env } from '../../../config';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    user: Joi.object().keys({
      email: Joi.string().email().required(),
    }),
  }),
});

async function resendEmailVerification(email: string): Promise<void> {
  const existingUser = await User.findOne({ email }).select(
    '+emailVerificationToken +emailVerificationTokenExpires',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (existingUser.isEmailVerified) {
    throw new BadRequestError('Email already verified');
  }

  if (
    existingUser.emailVerificationTokenExpires &&
    existingUser.emailVerificationTokenExpires > new Date()
  ) {
    throw new BadRequestError('Email verification token already sent.');
  }

  const payload = await generatePayload(existingUser);
  existingUser.emailVerificationToken = generateEmailVerificationToken(payload);
  existingUser.emailVerificationTokenExpires = new Date(
    Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
  );
  await existingUser.save();

  const user = excludeSensitiveFields(existingUser.toObject());

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED, {
    user,
    emailVerificationToken: existingUser.emailVerificationToken,
    tokenExpiresInSeconds: env.auth.emailVerificationTokenExpiresInSeconds,
  });

  return;
}

const resendEmailVerificationHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const { user } = req.body;

    await resendEmailVerification(user.email);

    res
      .status(200)
      .json({ message: 'Email verification link sent successfully' });
  } catch (err) {
    next(err);
  }
};

export default [
  emailRateLimiter,
  validatorMiddleware,
  resendEmailVerificationHandler,
];
