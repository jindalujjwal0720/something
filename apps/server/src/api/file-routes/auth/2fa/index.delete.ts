import { RequestHandler } from 'express';
import {
  Disable2FAConfig,
  Disable2FADTO,
} from '../../../../types/services/auth';
import User from '../../../../models/user';
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

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function disable2FA(
  userDTO: Disable2FADTO,
  config: Disable2FAConfig,
): Promise<void> {
  const { email, password } = userDTO;
  const existingUser = await User.findOne({ email }).select(
    '+twoFactorAuth +passwordHash +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (!existingUser.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA not enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  existingUser.twoFactorAuth.enabled = false;
  // Disable OTP if enabled
  existingUser.twoFactorAuth.otp.hash = undefined;
  existingUser.twoFactorAuth.otp.expires = undefined;
  // Disable TOTP if enabled
  existingUser.twoFactorAuth.totp.enabled = false;
  existingUser.twoFactorAuth.totp.secret = undefined;
  // Clear recovery codes
  existingUser.recoveryDetails = {
    backupCodes: [],
  };
  await existingUser.save();
  // Publish events
  EventBus.auth.emit(AuthenticationEvent.TWO_FACTOR_AUTH_DISABLED, {
    user: { name: existingUser.name, email: existingUser.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });
}

const disable2faHandler: RequestHandler = async (req, res, next) => {
  try {
    const data = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    await disable2FA(data, {
      deviceInfo,
      ipInfo,
    });

    res.status(200).json({ message: '2FA disabled successfully' });
  } catch (err) {
    next(err);
  }
};

export const handler = [extractIpInfo, validatorMiddleware, disable2faHandler];
