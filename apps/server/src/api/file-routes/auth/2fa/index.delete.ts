import { RequestHandler } from 'express';
import Account from '../../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../utils/errors';
import { comparePasswords } from '../../../../utils/auth';
import { AuthenticationEvent } from '../../../../events/auth/events';
import { EventBus } from '../../../../events/bus';
import { extractIpInfo } from '../../../middlewares/user-agent';
import Joi from 'joi';
import { celebrate, Segments } from 'celebrate';
import User from '../../../../models/user';
import {
  IDeviceInfo,
  IUserIPInfo,
} from '../../../../types/middlewares/user-agent';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function disable2FA(
  creds: { email: string; password: string },
  config: { deviceInfo: IDeviceInfo; ipInfo: IUserIPInfo },
): Promise<void> {
  const { email, password } = creds;
  const account = await Account.findOne({ email }).select(
    '+twoFactorAuth +passwordHash +recoveryDetails',
  );
  if (!account) throw new NotFoundError('Account not found');

  if (!account.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA not enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  account.twoFactorAuth.enabled = false;
  // Disable OTP if enabled
  account.twoFactorAuth.otp.hash = undefined;
  account.twoFactorAuth.otp.expires = undefined;
  // Disable TOTP if enabled
  account.twoFactorAuth.totp.enabled = false;
  account.twoFactorAuth.totp.secret = undefined;
  // Clear recovery codes
  account.recoveryDetails = {
    backupCodes: [],
  };
  await account.save();

  const user = await User.findOne({ account: account._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.TWO_FACTOR_AUTH_DISABLED, {
    user: { name: user.name, email: account.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });
}

const disable2faHandler: RequestHandler = async (req, res, next) => {
  try {
    const data = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    await disable2FA(data, { deviceInfo, ipInfo });

    res.status(200).json({ message: '2FA disabled successfully' });
  } catch (err) {
    next(err);
  }
};

export default [extractIpInfo, validatorMiddleware, disable2faHandler];
