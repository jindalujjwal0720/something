import { RequestHandler } from 'express';
import Account from '../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../utils/errors';
import {
  comparePasswords,
  excludeSensitiveFields,
  hashPassword,
} from '../../../utils/auth';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import Joi from 'joi';
import { celebrate, Segments } from 'celebrate';
import { extractIpInfo } from '../../middlewares/user-agent';
import User from '../../../models/user';
import {
  IDeviceInfo,
  IUserIPInfo,
} from '../../../types/middlewares/user-agent';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    account: Joi.object().keys({
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
    }),
    logoutAllDevices: Joi.boolean().optional(),
  }),
});

async function resetPassword(
  data: {
    account: {
      email: string;
      currentPasswordOrToken: string;
      newPassword: string;
    };
    logoutAllDevices?: boolean;
  },
  config: { deviceInfo: IDeviceInfo; ipInfo: IUserIPInfo },
): Promise<void> {
  const account = await Account.findOne({ email: data.account.email }).select(
    '+passwordHash +resetPasswordToken +resetPasswordTokenExpires',
  );
  if (!account) throw new NotFoundError('Account not found');

  // will be true if token is valid and not expired
  let isTokenValid =
    account.resetPasswordToken === data.account.currentPasswordOrToken &&
    account.resetPasswordTokenExpires &&
    account.resetPasswordTokenExpires > new Date();

  // check if it's the current password
  const passwordsMatch = await comparePasswords(
    data.account.currentPasswordOrToken,
    account.passwordHash || '',
  );

  if (!isTokenValid && !passwordsMatch) {
    throw new UnauthorizedError('Your current password or token is incorrect');
  }

  // don't allow to reset password with the same password
  if (
    await comparePasswords(data.account.newPassword, account.passwordHash || '')
  ) {
    throw new BadRequestError(
      'New password cannot be the same as the current password',
    );
  }

  const hashedPassword = await hashPassword(data.account.newPassword);
  account.passwordHash = hashedPassword;
  // logout all devices if requested
  if (data.logoutAllDevices) {
    account.refreshTokens = [];
  }
  account.resetPasswordToken = undefined;
  account.resetPasswordTokenExpires = undefined;
  await account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.PASSWORD_CHANGED, {
    user: { name: user.name, email: sanitisedAccount.email },
    deviceInfo: config.deviceInfo,
    ipInfo: config.ipInfo,
  });
}

const resetPasswordHandler: RequestHandler = async (req, res, next) => {
  try {
    const { account, logoutAllDevices } = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    await resetPassword({ account, logoutAllDevices }, { deviceInfo, ipInfo });

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, extractIpInfo, resetPasswordHandler];
