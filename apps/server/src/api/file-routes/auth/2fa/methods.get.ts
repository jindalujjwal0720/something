import { RequestHandler } from 'express';
import User from '../../../../models/user';
import { BadRequestError, NotFoundError } from '../../../../utils/errors';
import { verify2FAToken } from '../../../../utils/auth';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.QUERY]: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

async function list2faLoginMethods(token: string): Promise<string[]> {
  const { email } = await verify2FAToken(token);

  const existingUser = await User.findOne({ email }).select(
    '+twoFactorAuth +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (!existingUser.twoFactorAuth?.enabled) {
    throw new BadRequestError('2FA not enabled for the user');
  }

  const methods: string[] = ['otp']; // OTP based 2FA enabled by default
  methods.push('recovery'); // Recovery codes are always available
  if (existingUser.twoFactorAuth.totp?.enabled) {
    methods.push('totp');
  }
  if (existingUser.recoveryDetails?.emailVerified) {
    methods.push('recovery-email');
  }

  return methods;
}

const list2faMethodsHandler: RequestHandler = async (req, res, next) => {
  try {
    const { token } = req.query;

    const loginMethods = await list2faLoginMethods((token || '') as string);

    res.status(200).json({ methods: loginMethods });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, list2faMethodsHandler];
