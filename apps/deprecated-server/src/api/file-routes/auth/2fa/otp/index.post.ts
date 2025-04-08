import { RequestHandler } from 'express';
import {
  excludeSensitiveFields,
  generateRandomOTP,
  hashPassword,
  verify2FAToken,
} from '../../../../../utils/auth';
import Account from '../../../../../models/account';
import { BadRequestError, NotFoundError } from '../../../../../utils/errors';
import { env } from '../../../../../config';
import { EventBus } from '../../../../../events/bus';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { celebrate, Joi, Segments } from 'celebrate';
import { emailRateLimiter } from '../../../../middlewares/rate-limit';
import User from '../../../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function sendLoginOtp(token: string): Promise<{ expires: Date }> {
  const { email } = await verify2FAToken(token);

  const account = await Account.findOne({ email }).select('+twoFactorAuth');
  if (!account) {
    throw new NotFoundError('User not found');
  }

  if (!account.twoFactorAuth?.enabled || !account.twoFactorAuth.otp.enabled) {
    throw new BadRequestError('OTP based 2FA not enabled for this user');
  }

  if (
    account.twoFactorAuth.otp.expires &&
    account.twoFactorAuth.otp.expires > new Date()
  ) {
    throw new BadRequestError(
      'You already have an active OTP. Please wait for it to expire.',
    );
  }

  const otp = await generateRandomOTP();
  account.twoFactorAuth.otp.hash = await hashPassword(otp);
  account.twoFactorAuth.otp.expires = new Date(
    Date.now() + env.twoFactorAuth.otp.expiresInSeconds * 1000,
  );
  await account.save();
  const sanitizedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitizedAccount._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.TWO_FACTOR_AUTH_OTP_GENERATED, {
    user: { name: user.name, email: account.email },
    otp,
    optExpiresInSeconds: env.twoFactorAuth.otp.expiresInSeconds,
  });

  return { expires: account.twoFactorAuth.otp.expires };
}

const sendLoginOtpHandler: RequestHandler = async (req, res, next) => {
  try {
    const { token } = req.body;

    const { expires } = await sendLoginOtp(token);

    res.status(200).json({ message: 'OTP sent successfully', expires });
  } catch (err) {
    next(err);
  }
};

export default [emailRateLimiter, validatorMiddleware, sendLoginOtpHandler];
