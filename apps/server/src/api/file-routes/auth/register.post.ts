import { RequestHandler } from 'express';
import Joi from 'joi';
import { ConflictError } from '../../../utils/errors';
import { IAccount } from '../../../types/models/account';
import { EventBus } from '../../../events/bus';
import Account from '../../../models/account';
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
import User from '../../../models/user';
import { IUser } from '../../../types/models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    user: Joi.object().keys({
      name: Joi.string().required().min(3).max(50),
      imageUrl: Joi.string().optional().uri(),
    }),
    account: Joi.object().keys({
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
    }),
  }),
});

async function register(
  userInfo: Partial<IUser>,
  accountInfo: Pick<IAccount, 'email'> & { password: string },
): Promise<void> {
  const existingAccount = await Account.findOne({
    email: accountInfo.email,
  });
  if (existingAccount) {
    throw new ConflictError('User with this email already exists');
  }

  const hashedPassword = await hashPassword(accountInfo.password);
  const createdAccount = new Account({
    ...accountInfo,
    password: undefined,
    passwordHash: hashedPassword,
    role: 'user',
  });

  const payload = await generatePayload(createdAccount);
  createdAccount.emailVerificationToken =
    generateEmailVerificationToken(payload);
  createdAccount.emailVerificationTokenExpires = new Date(
    Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
  );
  await createdAccount.save();

  const createdUser = await User.create({
    ...userInfo,
    account: createdAccount._id,
  });

  const sanitisedAccount = excludeSensitiveFields(createdAccount.toObject());

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED, {
    user: { name: createdUser.name, email: sanitisedAccount.email },
    emailVerificationToken: createdAccount.emailVerificationToken as string,
    tokenExpiresInSeconds: env.auth.emailVerificationTokenExpiresInSeconds,
  });
  EventBus.auth.emit(AuthenticationEvent.REGISTERED, {
    user: { name: createdUser.name, email: sanitisedAccount.email },
  });
}

const registerHandler: RequestHandler = async (req, res, next) => {
  try {
    const { user, account } = req.body;
    await register(user, account);

    res.status(201).send();
  } catch (err) {
    next(err);
  }
};

export default [emailRateLimiter, validatorMiddleware, registerHandler];
