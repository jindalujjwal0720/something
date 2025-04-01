import { RequestHandler } from 'express';
import Joi from 'joi';
import {
  BadRequestError,
  CommonErrors,
  NotFoundError,
  UnauthorizedError,
} from '../../../utils/errors';
import { EventBus } from '../../../events/bus';
import User from '../../../models/user';
import {
  checkSameDevice,
  comparePasswords,
  excludeSensitiveFields,
  generate2FAAccessToken,
  generateAccessToken,
  generateAccountChooser,
  generateAccountChooserCookieOptions,
  generatePayload,
  generateRefreshToken,
  generateRefreshTokenCookieOptions,
  getAccountChooserCookieValue,
  getAllRefreshTokensMapping,
} from '../../../utils/auth';
import { AuthenticationEvent } from '../../../events/auth/events';
import { env } from '../../../config';
import { IDeviceInfo } from '../../../types/middlewares/user-agent';
import {
  UserLoginConfig,
  UserLoginDTO,
  UserLoginResponse,
} from '../../../types/services/auth';
import { encryptCookieValue } from '../../../utils/cookie';
import { celebrate, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    user: Joi.object().keys({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    }),
  }),
});

async function loginWithEmailAndPassword(
  userDTO: UserLoginDTO,
  config: UserLoginConfig,
): Promise<UserLoginResponse> {
  const existingUser = await User.findOne({ email: userDTO.email }).select(
    '+passwordHash +refreshTokens +twoFactorAuth',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  const passwordsMatch = await comparePasswords(
    userDTO.password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Invalid email or password');
  }

  if (!existingUser.isEmailVerified) {
    throw new BadRequestError('Email not verified. Please verify your email');
  }

  // Filter expired refresh tokens
  existingUser.refreshTokens =
    existingUser.refreshTokens?.filter((rt) => rt.expires > new Date()) || [];
  // Check if device already present
  const existingRefreshToken = existingUser.refreshTokens?.find((rt) =>
    checkSameDevice(config.deviceInfo, rt),
  );
  if (existingRefreshToken) {
    const payload = await generatePayload(existingUser);
    const accessToken = await generateAccessToken(payload);
    const encodedRefreshToken = Buffer.from(
      JSON.stringify(existingRefreshToken),
    ).toString('base64');

    const userObject = excludeSensitiveFields(existingUser.toObject());
    return {
      user: userObject,
      accessToken,
      refreshToken: encodedRefreshToken,
    };
  }

  // if 2FA is enabled
  // send a short access token to be used for getting user's details
  if (existingUser.twoFactorAuth?.enabled) {
    const payload = await generatePayload(existingUser);
    const token = await generate2FAAccessToken(payload);
    return { requires2FA: true, token };
  }

  const payload = await generatePayload(existingUser);
  const accessToken = await generateAccessToken(payload);
  const refreshToken = await generateRefreshToken(payload, config.deviceInfo);

  existingUser.refreshTokens?.push(refreshToken);
  await existingUser.save();

  const userObject = excludeSensitiveFields(existingUser.toObject());

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.LOGGED_IN, {
    user: { name: userObject.name, email: userObject.email },
    deviceInfo: config.deviceInfo,
  });

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(refreshToken),
  ).toString('base64');
  return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
}

const loginHandler: RequestHandler = async (req, res, next) => {
  try {
    const { user: userData } = req.body;

    const { useragent } = res.locals;
    const deviceInfo: IDeviceInfo = {
      browser: useragent?.browser || 'unknown',
      os: useragent?.os || 'unknown',
      platform: useragent?.platform || 'unknown',
      source: useragent?.source || 'unknown',
    };

    const response = await loginWithEmailAndPassword(userData, { deviceInfo });

    if ('requires2FA' in response) {
      const { requires2FA, token } = response;
      res
        .status(CommonErrors.Unauthorized.statusCode)
        .json({ requires2FA, token });
      return;
    }

    const { user, accessToken, refreshToken } = response;
    const {
      [env.auth.accountChooserCookieName]: existingAccountChooserCookie,
    } = req.cookies;

    const existingAccountChooser = await getAccountChooserCookieValue(
      existingAccountChooserCookie,
    );
    const refreshTokensMapping = await getAllRefreshTokensMapping(req);

    const { refreshTokenCookieName, accountChooser } =
      await generateAccountChooser(
        refreshToken,
        existingAccountChooser,
        refreshTokensMapping,
      );
    const accountChooserCookieValue = await encryptCookieValue(
      JSON.stringify(accountChooser),
    );

    res
      .status(200)
      .cookie(
        env.auth.accountChooserCookieName,
        accountChooserCookieValue,
        generateAccountChooserCookieOptions(),
      )
      .cookie(
        refreshTokenCookieName,
        refreshToken,
        generateRefreshTokenCookieOptions(),
      )
      .json({ user, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, loginHandler];
