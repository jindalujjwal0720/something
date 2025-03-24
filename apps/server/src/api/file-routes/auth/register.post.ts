import { RequestHandler } from 'express';
import Joi from 'joi';
import { ConflictError } from '../../../utils/errors';
import { UserRegisterDTO } from '../../../types/services/auth';
import { IUser } from '../../../types/models/user';
import { EventBus } from '../../../events/bus';
import User from '../../../models/user';
import {
  excludeSensitiveFields,
  generateEmailVerificationToken,
  generatePayload,
  hashPassword,
} from '../../../utils/auth';
import { AuthenticationEvent } from '../../../events/auth/events';
import { env } from '../../../config';
import { emailRateLimiter } from '../../middlewares/rate-limit';
import { celebrate, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    user: Joi.object().keys({
      name: Joi.string().required().min(3).max(50),
      email: Joi.string().email().required(),
      password: Joi.string()
        .required()
        .min(8)
        .pattern(
          new RegExp(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
          ),
        )
        .messages({
          'string.pattern.base':
            'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character(#@$!%*?&)',
        }),
      confirmPassword: Joi.string()
        .required()
        .valid(Joi.ref('password'))
        .messages({ 'any.only': 'Passwords do not match' }),
      imageUrl: Joi.string().optional().uri(),
    }),
  }),
});

async function register(userDTO: UserRegisterDTO): Promise<{ user: IUser }> {
  const existingUser = await User.findOne({
    email: userDTO.email,
  });
  if (existingUser) {
    throw new ConflictError('User with this email already exists');
  }

  const hashedPassword = await hashPassword(userDTO.password);
  const createdUser = new User({
    ...userDTO,
    password: undefined,
    passwordHash: hashedPassword,
    role: 'user',
  });

  const payload = await generatePayload(createdUser);
  createdUser.emailVerificationToken = generateEmailVerificationToken(payload);
  createdUser.emailVerificationTokenExpires = new Date(
    Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
  );
  await createdUser.save();

  const user = excludeSensitiveFields(createdUser.toObject());

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED, {
    user,
    emailVerificationToken: createdUser.emailVerificationToken as string,
    tokenExpiresInSeconds: env.auth.emailVerificationTokenExpiresInSeconds,
  });
  EventBus.auth.emit(AuthenticationEvent.REGISTERED, { user });

  return { user };
}

const registerHandler: RequestHandler = async (req, res, next) => {
  try {
    const { user } = req.body;
    const { user: registeredUser } = await register(user);

    res.status(201).json({ user: registeredUser });
  } catch (err) {
    next(err);
  }
};

export const handler = [emailRateLimiter, validatorMiddleware, registerHandler];
