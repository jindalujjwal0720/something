import { RequestHandler } from 'express';
import { emailRateLimiter } from '../../middlewares/rate-limit';
import { BadRequestError, NotFoundError } from '../../../utils/errors';
import Account from '../../../models/account';
import {
  excludeSensitiveFields,
  generateEmailVerificationToken,
  generatePayload,
} from '../../../utils/auth';
import { env } from '../../../config';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';
import User from '../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    account: Joi.object().keys({
      email: Joi.string().email().required(),
    }),
  }),
});

async function resendEmailVerification(email: string): Promise<void> {
  const account = await Account.findOne({ email }).select(
    '+emailVerificationToken +emailVerificationTokenExpires',
  );
  if (!account) {
    throw new NotFoundError('Account not found');
  }

  if (account.isEmailVerified) {
    throw new BadRequestError('Email already verified.');
  }

  if (
    account.emailVerificationTokenExpires &&
    account.emailVerificationTokenExpires > new Date()
  ) {
    throw new BadRequestError('Email verification token already sent.');
  }

  const payload = await generatePayload(account);
  account.emailVerificationToken = generateEmailVerificationToken(payload);
  account.emailVerificationTokenExpires = new Date(
    Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
  );
  await account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED, {
    user: { name: user.name, email: account.email },
    emailVerificationToken: account.emailVerificationToken,
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
    const { account } = req.body;

    await resendEmailVerification(account.email);

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
