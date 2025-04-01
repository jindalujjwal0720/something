import { RequestHandler } from 'express';
import { env } from '../../../../../config';
import { NotFoundError, UnauthorizedError } from '../../../../../utils/errors';
import User from '../../../../../models/user';
import { verifyRecoveryEmailVerificationToken } from '../../../../../utils/auth';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.QUERY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function verifyAndUpdateRecoveryEmail(token: string): Promise<void> {
  const payload = await verifyRecoveryEmailVerificationToken(token);
  if (!payload) {
    throw new UnauthorizedError(
      'Invalid or expired recovery email verification token',
    );
  }

  const existingUser = await User.findOne({ email: payload.email }).select(
    '+recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  existingUser.recoveryDetails = {
    ...(existingUser.recoveryDetails || {
      backupCodes: [],
    }),
    email: payload.recoveryEmail,
    emailVerified: true,
  };
  await existingUser.save();
}

const verifyRecoveryEmailHandler: RequestHandler = async (req, res, next) => {
  try {
    const { token } = req.query;

    await verifyAndUpdateRecoveryEmail(token as string);

    res.status(200).redirect(`${env.client.url}`);
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, verifyRecoveryEmailHandler];
