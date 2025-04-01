import { RequestHandler } from 'express';
import Joi from 'joi';
import {
  BadRequestError,
  CommonErrors,
  NotFoundError,
  UnauthorizedError,
} from '../../../utils/errors';
import { EventBus } from '../../../events/bus';
import Account from '../../../models/account';
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
import { encryptCookieValue } from '../../../utils/cookie';
import { celebrate, Segments } from 'celebrate';
import User from '../../../models/user';
import { SanitisedAccount } from '../../../types/models/account';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    account: Joi.object().keys({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    }),
  }),
});

async function loginWithEmailAndPassword(
  accountInfo: { email: string; password: string },
  config: { deviceInfo: IDeviceInfo },
): Promise<
  | {
      account: SanitisedAccount;
      accessToken: string;
      refreshToken: string;
    }
  | { requires2FA: boolean; token: string }
> {
  const account = await Account.findOne({
    email: accountInfo.email,
  }).select('+passwordHash +refreshTokens +twoFactorAuth');
  if (!account) {
    throw new NotFoundError('Invalid email or password');
  }

  const passwordsMatch = await comparePasswords(
    accountInfo.password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Invalid email or password');
  }

  if (!account.isEmailVerified) {
    throw new BadRequestError('Email not verified. Please verify your email');
  }

  // Filter expired refresh tokens
  account.refreshTokens =
    account.refreshTokens?.filter((rt) => rt.expires > new Date()) || [];
  // Check if device already present
  const existingRefreshToken = account.refreshTokens?.find((rt) =>
    checkSameDevice(config.deviceInfo, rt),
  );
  if (existingRefreshToken) {
    const payload = await generatePayload(account);
    const accessToken = await generateAccessToken(payload);
    const encodedRefreshToken = Buffer.from(
      JSON.stringify(existingRefreshToken),
    ).toString('base64');

    const sanitisedAccount = excludeSensitiveFields(account.toObject());

    return {
      account: sanitisedAccount,
      accessToken,
      refreshToken: encodedRefreshToken,
    };
  }

  // if 2FA is enabled
  // send a short access token to be used for getting user's details
  if (account.twoFactorAuth?.enabled) {
    const payload = await generatePayload(account);
    const token = await generate2FAAccessToken(payload);
    return { requires2FA: true, token };
  }

  const payload = await generatePayload(account);
  const accessToken = await generateAccessToken(payload);
  const refreshToken = await generateRefreshToken(payload, config.deviceInfo);

  account.refreshTokens?.push(refreshToken);
  await account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) {
    throw new NotFoundError('User not found');
  }

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.LOGGED_IN, {
    user: { name: user.name, email: sanitisedAccount.email },
    deviceInfo: config.deviceInfo,
  });

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(refreshToken),
  ).toString('base64');
  return {
    account: sanitisedAccount,
    accessToken,
    refreshToken: encodedRefreshToken,
  };
}

const loginHandler: RequestHandler = async (req, res, next) => {
  try {
    const { account } = req.body;

    const { useragent } = res.locals;
    const deviceInfo: IDeviceInfo = {
      browser: useragent?.browser || 'unknown',
      os: useragent?.os || 'unknown',
      platform: useragent?.platform || 'unknown',
      source: useragent?.source || 'unknown',
    };

    const response = await loginWithEmailAndPassword(account, { deviceInfo });

    if ('requires2FA' in response) {
      const { requires2FA, token } = response;
      res
        .status(CommonErrors.Unauthorized.statusCode)
        .json({ requires2FA, token });
      return;
    }

    const { accessToken, refreshToken } = response;
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
      .json({ token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, loginHandler];
