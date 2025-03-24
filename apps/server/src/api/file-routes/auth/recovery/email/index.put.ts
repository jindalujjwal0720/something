import { RequestHandler } from 'express';
import { UpdateRecoveryEmailDTO } from '../../../../../types/services/auth';
import User from '../../../../../models/user';
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

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    newRecoveryEmail: Joi.string().email().required(),
  }),
});

async function requestRecoveryEmailUpdate(
  userDTO: UpdateRecoveryEmailDTO,
): Promise<void> {
  const existingUser = await User.findOne({ email: userDTO.email }).select(
    '+passwordHash +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  const passwordsMatch = await comparePasswords(
    userDTO.password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  if (existingUser.recoveryDetails?.email === userDTO.newRecoveryEmail) {
    throw new BadRequestError('Recovery email is already set for this email');
  }

  const payload = await generatePayload(existingUser);
  const recoveryEmailVerificationToken =
    await generateRecoveryEmailVerificationToken({
      ...payload,
      recoveryEmail: userDTO.newRecoveryEmail,
    });

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.RECOVERY_EMAIL_UPDATE_REQUESTED, {
    user: { name: existingUser.name, email: existingUser.email },
    recoveryEmail: userDTO.newRecoveryEmail,
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

export const handler = [
  emailRateLimiter,
  validatorMiddleware,
  requestRecoveryEmailUpdateHandler,
];
