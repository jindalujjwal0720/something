import { RequestHandler } from 'express';
import { NotFoundError } from '../../../utils/errors';
import {
  generatePayload,
  generateResetPasswordToken,
} from '../../../utils/auth';
import { env } from '../../../config';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import Account from '../../../models/account';
import { celebrate, Joi, Segments } from 'celebrate';
import { emailRateLimiter } from '../../middlewares/rate-limit';
import User from '../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    logoutAllDevices: Joi.boolean().optional(),
  }),
});

async function requestPasswordReset(data: {
  email: string;
  logoutAllDevices?: boolean;
}) {
  const account = await Account.findOne({
    email: data.email,
  }).select('+refreshTokens +resetPasswordToken +resetPasswordTokenExpires');
  if (!account) {
    throw new NotFoundError('Account not found');
  }

  const payload = await generatePayload(account);
  const resetPasswordToken = generateResetPasswordToken(payload);
  account.resetPasswordToken = resetPasswordToken;
  account.resetPasswordTokenExpires = new Date(
    Date.now() + env.auth.resetPasswordTokenExpiresInSeconds * 1000,
  );
  if (data.logoutAllDevices) {
    account.refreshTokens = [];
  }
  await account.save();

  const user = await User.findOne({ account: account._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.PASSWORD_CHANGE_REQUESTED, {
    user: { name: user.name, email: account.email },
    resetPasswordToken,
    tokenExpiresInSeconds: env.auth.resetPasswordTokenExpiresInSeconds,
  });
}

const requestResetPasswordHandler: RequestHandler = async (req, res, next) => {
  try {
    const { email, logoutAllDevices } = req.body;

    await requestPasswordReset({ email: email, logoutAllDevices });

    res.status(200).json({ message: 'Password reset request sent' });
  } catch (err) {
    next(err);
  }
};

export default [
  emailRateLimiter,
  validatorMiddleware,
  requestResetPasswordHandler,
];
