import { RequestHandler } from 'express';
import {
  ResetPasswordConfig,
  ResetPasswordDTO,
} from '../../../types/services/auth';
import User from '../../../models/user';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../utils/errors';
import { comparePasswords, hashPassword } from '../../../utils/auth';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import Joi from 'joi';
import { celebrate, Segments } from 'celebrate';
import { extractIpInfo } from '../../middlewares/user-agent';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    user: Joi.object().keys({
      email: Joi.string().email().required(),
      currentPasswordOrToken: Joi.string().required(),
      newPassword: Joi.string()
        .required()
        .min(8)
        .pattern(
          new RegExp(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
          ),
        )
        .messages({
          'string.pattern.base':
            'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character(#@$!%*?&)',
        }),
      confirmPassword: Joi.string()
        .required()
        .valid(Joi.ref('newPassword'))
        .messages({ 'any.only': 'Passwords do not match' }),
    }),
    logoutAllDevices: Joi.boolean().optional(),
  }),
});

async function resetPassword(
  data: ResetPasswordDTO,
  config: ResetPasswordConfig,
): Promise<void> {
  const existingUser = await User.findOne({ email: data.user.email }).select(
    '+passwordHash +resetPasswordToken +resetPasswordTokenExpires',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  // will be true if token is valid and not expired
  let isTokenValid =
    existingUser.resetPasswordToken === data.user.currentPasswordOrToken &&
    existingUser.resetPasswordTokenExpires &&
    existingUser.resetPasswordTokenExpires > new Date();

  // check if it's the current password
  const passwordsMatch = await comparePasswords(
    data.user.currentPasswordOrToken,
    existingUser.passwordHash || '',
  );

  if (!isTokenValid && !passwordsMatch) {
    throw new UnauthorizedError('Your current password or token is incorrect');
  }

  // don't allow to reset password with the same password
  if (
    await comparePasswords(
      data.user.newPassword,
      existingUser.passwordHash || '',
    )
  ) {
    throw new BadRequestError(
      'New password cannot be the same as the current password',
    );
  }

  const hashedPassword = await hashPassword(data.user.newPassword);
  existingUser.passwordHash = hashedPassword;
  // logout all devices if requested
  if (data.logoutAllDevices) {
    existingUser.refreshTokens = [];
  }
  existingUser.resetPasswordToken = undefined;
  existingUser.resetPasswordTokenExpires = undefined;
  await existingUser.save();

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.PASSWORD_CHANGED, {
    user: { name: existingUser.name, email: existingUser.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });
}

const resetPasswordHandler: RequestHandler = async (req, res, next) => {
  try {
    const { user, logoutAllDevices } = req.body;
    const { deviceInfo, ipInfo } = res.locals;
    const defaultIpInfo = {
      ip: 'unknown',
      location: {
        country: 'unknown',
        state: 'unknown',
        city: 'unknown',
        zip: 'unknown',
        timezone: 'unknown',
      },
    };

    await resetPassword(
      {
        user,
        logoutAllDevices,
      },
      {
        deviceInfo,
        ipInfo: ipInfo || defaultIpInfo,
      },
    );

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, extractIpInfo, resetPasswordHandler];
