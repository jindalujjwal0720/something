import { RequestHandler } from 'express';
import Account from '../../../../../models/account';
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

async function enable2faTotp(creds: {
  email: string;
  password: string;
}): Promise<{ otpAuthUrl: string }> {
  const { email, password } = creds;
  const account = await Account.findOne({ email }).select(
    '+twoFactorAuth +passwordHash',
  );
  if (!account) {
    throw new NotFoundError('User not found');
  }

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

  if (account.twoFactorAuth.totp.enabled) {
    throw new BadRequestError('Authenticator already enabled for the user');
  }

  const secret = authenticator.generateSecret();
  const encodedSecret = await encrypt2FATOTPSecret(secret);
  account.twoFactorAuth.totp.secret = encodedSecret;
  account.twoFactorAuth.totp.enabled = true;
  await account.save();

  // Generate QR code for the user
  const otpAuthUrl = authenticator.keyuri(email, meta.company.name, secret);

  // Publish events

  return { otpAuthUrl };
}

const enable2faTotpHandler: RequestHandler = async (req, res, next) => {
  try {
    const creds = req.body;

    const { otpAuthUrl } = await enable2faTotp(creds);

    res.status(200).json({ otpAuthUrl });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, enable2faTotpHandler];
