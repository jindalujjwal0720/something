import { RequestHandler } from 'express';
import { NotFoundError } from '../../../utils/errors';
import {
  generatePayload,
  generateResetPasswordToken,
} from '../../../utils/auth';
import { env } from '../../../config';
import { AuthenticationEvent } from '../../../events/auth/events';
import { EventBus } from '../../../events/bus';
import User from '../../../models/user';
import { RequestPasswordResetDTO } from '../../../types/services/auth';
import { celebrate, Joi, Segments } from 'celebrate';
import { emailRateLimiter } from '../../middlewares/rate-limit';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    logoutAllDevices: Joi.boolean().optional(),
  }),
});

async function requestPasswordReset(data: RequestPasswordResetDTO) {
  const existingUser = await User.findOne({
    email: data.email,
  }).select('+refreshTokens +resetPasswordToken +resetPasswordTokenExpires');
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  const payload = await generatePayload(existingUser);
  const resetPasswordToken = generateResetPasswordToken(payload);
  existingUser.resetPasswordToken = resetPasswordToken;
  existingUser.resetPasswordTokenExpires = new Date(
    Date.now() + env.auth.resetPasswordTokenExpiresInSeconds * 1000,
  );
  if (data.logoutAllDevices) {
    existingUser.refreshTokens = [];
  }
  await existingUser.save();

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.PASSWORD_CHANGE_REQUESTED, {
    user: { name: existingUser.name, email: existingUser.email },
    resetPasswordToken,
    tokenExpiresInSeconds: env.auth.resetPasswordTokenExpiresInSeconds,
  });
}

const requestResetPasswordHandler: RequestHandler = async (req, res, next) => {
  try {
    const { email, logoutAllDevices } = req.body;

    await requestPasswordReset({
      email: email,
      logoutAllDevices,
    });

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
