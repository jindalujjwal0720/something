import { RequestHandler } from 'express';
import Account from '../../../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import { comparePasswords } from '../../../../../utils/auth';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function disable2faTotp(creds: {
  email: string;
  password: string;
}): Promise<void> {
  const { email, password } = creds;
  const account = await Account.findOne({ email }).select(
    '+twoFactorAuth +passwordHash',
  );
  if (!account) throw new NotFoundError('Account not found');

  if (!account.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA not enabled for the user');
  }

  if (!account.twoFactorAuth.totp.enabled) {
    throw new BadRequestError('Authenticator not enabled for the user');
  }

  const passwordsMatch = await comparePasswords(
    password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  account.twoFactorAuth.totp.secret = undefined;
  account.twoFactorAuth.totp.enabled = false;
  await account.save();

  // Publish events
}

const disable2faTotpHandler: RequestHandler = async (req, res, next) => {
  try {
    const creds = req.body;

    await disable2faTotp(creds);

    res
      .status(200)
      .json({ message: '2FA Authenticator disabled successfully' });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, disable2faTotpHandler];
