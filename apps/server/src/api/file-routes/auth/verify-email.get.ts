import { RequestHandler } from 'express';
import { env } from '../../../config';
import Account from '../../../models/account';
import { BadRequestError, NotFoundError } from '../../../utils/errors';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.QUERY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function verifyEmail(token: string): Promise<void> {
  const account = await Account.findOne({
    emailVerificationToken: token,
  }).select('+emailVerificationToken +emailVerificationTokenExpires');

  if (!account) {
    throw new NotFoundError('Invalid or expired email verification token');
  }

  if (
    !account.emailVerificationTokenExpires ||
    account.emailVerificationTokenExpires < new Date()
  ) {
    throw new BadRequestError(
      'Email verification token expired. Please request a new one by logging in.',
    );
  }

  account.emailVerificationToken = undefined;
  account.emailVerificationTokenExpires = undefined;
  account.isEmailVerified = true;
  await account.save();
}

const verifyEmailHandler: RequestHandler = async (req, res, next) => {
  try {
    const { token } = req.query;

    await verifyEmail(token as string);

    return res.status(200).redirect(`${env.client.url}`);
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, verifyEmailHandler];
