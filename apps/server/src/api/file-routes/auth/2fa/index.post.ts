import { RequestHandler } from 'express';
import { Enable2FAConfig, Enable2FADTO } from '../../../../types/services/auth';
import User from '../../../../models/user';
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

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function enable2FA(
  userDTO: Enable2FADTO,
  config: Enable2FAConfig,
): Promise<{ recoveryCodes: string[] }> {
  const { email, password } = userDTO;
  const existingUser = await User.findOne({ email }).select(
    '+twoFactorAuth +passwordHash +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (existingUser.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA already enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  existingUser.twoFactorAuth = {
    enabled: true,
    otp: { enabled: true }, // OTP based 2FA enabled by default
    totp: { enabled: false },
  };
  const backupCodes = await generateBackupCodes();
  existingUser.recoveryDetails = {
    backupCodes: backupCodes.map((code) => ({ code })),
  };
  await existingUser.save();

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.TWO_FACTOR_AUTH_ENABLED, {
    user: { name: existingUser.name, email: existingUser.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });

  const decryptedCodes = await Promise.all(backupCodes.map(decryptBackupCode));
  return { recoveryCodes: decryptedCodes };
}

const enable2faHandler: RequestHandler = async (req, res, next) => {
  try {
    const data = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    const { recoveryCodes } = await enable2FA(data, {
      deviceInfo,
      ipInfo,
    });

    res.status(200).json({ recoveryCodes });
  } catch (err) {
    next(err);
  }
};

export const handler = [extractIpInfo, validatorMiddleware, enable2faHandler];
