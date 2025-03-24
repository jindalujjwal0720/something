import { RequestHandler } from 'express';
import { env } from '../../../config';
import User from '../../../models/user';
import { BadRequestError, NotFoundError } from '../../../utils/errors';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.QUERY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function verifyEmail(token: string): Promise<void> {
  const existingUser = await User.findOne({
    emailVerificationToken: token,
  }).select('+emailVerificationToken +emailVerificationTokenExpires');

  if (!existingUser) {
    throw new NotFoundError('Invalid or expired email verification token');
  }

  if (
    !existingUser.emailVerificationTokenExpires ||
    existingUser.emailVerificationTokenExpires < new Date()
  ) {
    throw new BadRequestError(
      'Email verification token expired. Please request a new one by logging in.',
    );
  }

  existingUser.emailVerificationToken = undefined;
  existingUser.emailVerificationTokenExpires = undefined;
  existingUser.isEmailVerified = true;
  await existingUser.save();
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

export const handler = [validatorMiddleware, verifyEmailHandler];
