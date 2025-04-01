import { RequestHandler } from 'express';
import Account from '../../../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import {
  comparePasswords,
  generatePayload,
  generateRecoveryEmailVerificationToken,
} from '../../../../../utils/auth';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { EventBus } from '../../../../../events/bus';
import { env } from '../../../../../config';
import { celebrate, Joi, Segments } from 'celebrate';
import { emailRateLimiter } from '../../../../middlewares/rate-limit';
import User from '../../../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    newRecoveryEmail: Joi.string().email().required(),
  }),
});

async function requestRecoveryEmailUpdate(recoveryEmailUpdateDTO: {
  email: string;
  password: string;
  newRecoveryEmail: string;
}): Promise<void> {
  const account = await Account.findOne({
    email: recoveryEmailUpdateDTO.email,
  }).select('+passwordHash +recoveryDetails');
  if (!account) throw new NotFoundError('Account not found');

  const passwordsMatch = await comparePasswords(
    recoveryEmailUpdateDTO.password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  if (
    account.recoveryDetails?.email === recoveryEmailUpdateDTO.newRecoveryEmail
  ) {
    throw new BadRequestError('Recovery email is already set for this email');
  }

  const payload = await generatePayload(account);
  const recoveryEmailVerificationToken =
    await generateRecoveryEmailVerificationToken({
      ...payload,
      recoveryEmail: recoveryEmailUpdateDTO.newRecoveryEmail,
    });

  const user = await User.findOne({ account: account._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.RECOVERY_EMAIL_UPDATE_REQUESTED, {
    user: { name: user.name, email: account.email },
    recoveryEmail: recoveryEmailUpdateDTO.newRecoveryEmail,
    emailVerificationToken: recoveryEmailVerificationToken,
    tokenExpiresInSeconds:
      env.auth.recoveryEmailVerificationTokenExpiresInSeconds,
  });
}

const requestRecoveryEmailUpdateHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const data = req.body;

    await requestRecoveryEmailUpdate(data);

    res.status(200).json({ message: 'Recovery email update request sent' });
  } catch (err) {
    next(err);
  }
};

export default [
  emailRateLimiter,
  validatorMiddleware,
  requestRecoveryEmailUpdateHandler,
];
