import { RequestHandler } from 'express';
import {
  excludeSensitiveFields,
  generateRandomOTP,
  hashPassword,
  verify2FAToken,
} from '../../../../../utils/auth';
import User from '../../../../../models/user';
import { BadRequestError, NotFoundError } from '../../../../../utils/errors';
import { env } from '../../../../../config';
import { EventBus } from '../../../../../events/bus';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { celebrate, Joi, Segments } from 'celebrate';
import { emailRateLimiter } from '../../../../middlewares/rate-limit';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function sendLoginOtpToRecoveryEmail(
  token: string,
): Promise<{ expires: Date }> {
  const { email } = await verify2FAToken(token);

  const existingUser = await User.findOne({ email }).select(
    '+twoFactorAuth +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (
    !existingUser.twoFactorAuth?.enabled ||
    !existingUser.twoFactorAuth.otp.enabled
  ) {
    throw new BadRequestError('OTP based 2FA not enabled for this user');
  }

  if (
    !existingUser.recoveryDetails?.email ||
    !existingUser.recoveryDetails?.emailVerified
  ) {
    throw new BadRequestError('Recovery email not verified');
  }

  if (
    existingUser.twoFactorAuth.otp.expires &&
    existingUser.twoFactorAuth.otp.expires > new Date()
  ) {
    throw new BadRequestError(
      'You already have an active OTP. Please wait for it to expire.',
    );
  }

  const otp = await generateRandomOTP();
  existingUser.twoFactorAuth.otp.hash = await hashPassword(otp);
  existingUser.twoFactorAuth.otp.expires = new Date(
    Date.now() + env.twoFactorAuth.otp.expiresInSeconds * 1000,
  );
  await existingUser.save();

  const user = excludeSensitiveFields(existingUser.toObject());

  // Publish events
  EventBus.auth.emit(
    AuthenticationEvent.TWO_FACTOR_AUTH_RECOVERY_OTP_GENERATED,
    {
      recoveryEmail: existingUser.recoveryDetails.email,
      user,
      otp,
      optExpiresInSeconds: env.twoFactorAuth.otp.expiresInSeconds,
    },
  );

  return { expires: existingUser.twoFactorAuth.otp.expires };
}

const sendLoginOtpHandler: RequestHandler = async (req, res, next) => {
  try {
    const { token } = req.body;

    const { expires } = await sendLoginOtpToRecoveryEmail(token);

    res
      .status(200)
      .json({ message: 'Recovery OTP sent successfully', expires });
  } catch (err) {
    next(err);
  }
};

export default [emailRateLimiter, validatorMiddleware, sendLoginOtpHandler];
