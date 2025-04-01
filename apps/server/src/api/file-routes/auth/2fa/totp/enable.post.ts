import { RequestHandler } from 'express';
import { Setup2FAAuthenticatorDTO } from '../../../../../types/services/auth';
import User from '../../../../../models/user';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import {
  comparePasswords,
  encrypt2FATOTPSecret,
} from '../../../../../utils/auth';
import { authenticator } from 'otplib';
import { meta } from '../../../../../config';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function enable2faTotp(
  userDTO: Setup2FAAuthenticatorDTO,
): Promise<{ otpAuthUrl: string }> {
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

  const passwordsMatch = await comparePasswords(
    password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  if (existingUser.twoFactorAuth.totp.enabled) {
    throw new BadRequestError('Authenticator already enabled for the user');
  }

  const secret = authenticator.generateSecret();
  const encodedSecret = await encrypt2FATOTPSecret(secret);
  existingUser.twoFactorAuth.totp.secret = encodedSecret;
  existingUser.twoFactorAuth.totp.enabled = true;
  await existingUser.save();

  // Generate QR code for the user
  const otpAuthUrl = authenticator.keyuri(email, meta.company.name, secret);

  // Publish events

  return { otpAuthUrl };
}

const enable2faTotpHandler: RequestHandler = async (req, res, next) => {
  try {
    const user = req.body;

    const { otpAuthUrl } = await enable2faTotp(user);

    res.status(200).json({ otpAuthUrl });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, enable2faTotpHandler];
