import { RequestHandler } from 'express';
import { env } from '../../../../../config';
import {
  checkSameDevice,
  decrypt2FATOTPSecret,
  excludeSensitiveFields,
  generateAccessToken,
  generateAccountChooser,
  generateAccountChooserCookieOptions,
  generatePayload,
  generateRefreshToken,
  generateRefreshTokenCookieOptions,
  getAccountChooserCookieValue,
  getAllRefreshTokensMapping,
  verify2FAToken,
} from '../../../../../utils/auth';
import { encryptCookieValue } from '../../../../../utils/cookie';
import { SanitisedAccount } from '../../../../../types/models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import Account from '../../../../../models/account';
import { authenticator } from 'otplib';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { EventBus } from '../../../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';
import { IDeviceInfo } from '../../../../../types/middlewares/user-agent';
import User from '../../../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
    otp: Joi.string().required(),
  }),
});

async function loginWithTotp(
  otpVerificationData: { otp: string; token: string },
  config: { deviceInfo: IDeviceInfo },
): Promise<{
  account: SanitisedAccount;
  accessToken: string;
  refreshToken: string;
}> {
  const { token, otp } = otpVerificationData;
  const twoFactorAuthPayload = await verify2FAToken(token);

  const account = await Account.findOne({
    email: twoFactorAuthPayload.email,
  }).select('+twoFactorAuth +refreshTokens');
  if (!account) {
    throw new NotFoundError('User not found');
  }

  if (!account.twoFactorAuth?.enabled || !account.twoFactorAuth.totp.enabled) {
    throw new BadRequestError(
      'Authenticator based 2FA not enabled for this user',
    );
  }

  if (
    !account.twoFactorAuth.totp.secret ||
    !account.twoFactorAuth.totp.enabled
  ) {
    throw new BadRequestError(
      'Authenticator not enabled. Please setup the authenticator first.',
    );
  }

  const secret = await decrypt2FATOTPSecret(account.twoFactorAuth.totp.secret);
  const otpMatch = authenticator.verify({ token: otp, secret });
  if (!otpMatch) {
    throw new UnauthorizedError('Incorrect OTP');
  }

  // Filter expired refresh tokens
  account.refreshTokens =
    account.refreshTokens?.filter((rt) => rt.expires > new Date()) || [];
  // Check if device already present
  const existingRefreshToken = account.refreshTokens?.find((rt) =>
    checkSameDevice(config.deviceInfo, rt),
  );
  if (existingRefreshToken) {
    const payload = await generatePayload(account, true);
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

  const payload = await generatePayload(account, true);
  const accessToken = await generateAccessToken(payload);
  const refreshToken = await generateRefreshToken(payload, config.deviceInfo);

  account.refreshTokens.push(refreshToken);
  account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) throw new NotFoundError('User not found');

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

const verifyTotpAndLoginHandler: RequestHandler = async (req, res, next) => {
  try {
    const { otp, token } = req.body;
    const { deviceInfo } = res.locals;

    const { account, accessToken, refreshToken } = await loginWithTotp(
      { otp, token },
      { deviceInfo },
    );

    // Account Chooser
    const { [env.auth.accountChooserCookieName]: accountChooserCookie } =
      req.cookies;
    const accountChooser =
      await getAccountChooserCookieValue(accountChooserCookie);

    const refreshTokensMapping = await getAllRefreshTokensMapping(req);

    const { refreshTokenCookieName, accountChooser: newAccountChooser } =
      await generateAccountChooser(
        refreshToken,
        accountChooser,
        refreshTokensMapping,
      );
    const accountChooserCookieValue = await encryptCookieValue(
      JSON.stringify(newAccountChooser),
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
      .json({ account, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, verifyTotpAndLoginHandler];
