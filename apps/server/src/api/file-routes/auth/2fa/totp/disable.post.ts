import { RequestHandler } from 'express';
import { extractDeviceInfo } from '../../../../middlewares/user-agent';
import User from '../../../../../models/user';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import { comparePasswords } from '../../../../../utils/auth';
import {
  Disable2FAConfig,
  Disable2FADTO,
} from '../../../../../types/services/auth';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function disable2faTotp(
  userDTO: Disable2FADTO,
  _config: Disable2FAConfig,
): Promise<void> {
  const { email, password } = userDTO;
  const existingUser = await User.findOne({ email }).select(
    '+twoFactorAuth +passwordHash',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (!existingUser.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA not enabled for the user');
  }

  if (!existingUser.twoFactorAuth.totp.enabled) {
    throw new BadRequestError('Authenticator not enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  existingUser.twoFactorAuth.totp.secret = undefined;
  existingUser.twoFactorAuth.totp.enabled = false;
  await existingUser.save();

  // Publish events
}

const disable2faTotpHandler: RequestHandler = async (req, res, next) => {
  try {
    const user = req.body;
    const { deviceInfo, ipInfo } = res.locals;

    await disable2faTotp(user, {
      deviceInfo,
      ipInfo,
    });

    res
      .status(200)
      .json({ message: '2FA Authenticator disabled successfully' });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, extractDeviceInfo, disable2faTotpHandler];
