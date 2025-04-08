import { RequestHandler } from 'express';
import Account from '../../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../utils/errors';
import {
  comparePasswords,
  decryptBackupCode,
  generateBackupCodes,
} from '../../../../utils/auth';
import { AuthenticationEvent } from '../../../../events/auth/events';
import { EventBus } from '../../../../events/bus';
import { extractIpInfo } from '../../../middlewares/user-agent';
import { celebrate, Joi, Segments } from 'celebrate';
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

async function enable2FA(
  creds: { email: string; password: string },
  config: { deviceInfo: IDeviceInfo; ipInfo: IUserIPInfo },
): Promise<{ recoveryCodes: string[] }> {
  const { email, password } = creds;
  const account = await Account.findOne({ email }).select(
    '+twoFactorAuth +passwordHash +recoveryDetails',
  );
  if (!account) throw new NotFoundError('Account not found');

  if (account.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA already enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  account.twoFactorAuth = {
    enabled: true,
    otp: { enabled: true }, // OTP based 2FA enabled by default
    totp: { enabled: false },
  };
  const backupCodes = await generateBackupCodes();
  account.recoveryDetails = {
    backupCodes: backupCodes.map((code) => ({ code })),
  };
  await account.save();

  const user = await User.findOne({ account: account._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.TWO_FACTOR_AUTH_ENABLED, {
    user: { name: user.name, email: account.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });

  const decryptedCodes = await Promise.all(backupCodes.map(decryptBackupCode));
  return { recoveryCodes: decryptedCodes };
}

const enable2faHandler: RequestHandler = async (req, res, next) => {
  try {
    const creds = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    const { recoveryCodes } = await enable2FA(creds, { deviceInfo, ipInfo });

    res.status(200).json({ recoveryCodes });
  } catch (err) {
    next(err);
  }
};

export default [extractIpInfo, validatorMiddleware, enable2faHandler];
