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
import {
  UserLoginConfig,
  UserOTPLoginDTO,
} from '../../../../../types/services/auth';
import { IUser } from '../../../../../types/models/user';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import User from '../../../../../models/user';
import { authenticator } from 'otplib';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { EventBus } from '../../../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
    otp: Joi.string().required(),
  }),
});

async function loginWithTotp(
  userDTO: UserOTPLoginDTO,
  config: UserLoginConfig,
): Promise<{
  user: IUser;
  accessToken: string;
  refreshToken: string;
}> {
  const { token, otp } = userDTO;
  const twoFactorAuthPayload = await verify2FAToken(token);

  const existingUser = await User.findOne({
    email: twoFactorAuthPayload.email,
  }).select('+twoFactorAuth +refreshTokens');
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (
    !existingUser.twoFactorAuth?.enabled ||
    !existingUser.twoFactorAuth.totp.enabled
  ) {
    throw new BadRequestError(
      'Authenticator based 2FA not enabled for this user',
    );
  }

  if (
    !existingUser.twoFactorAuth.totp.secret ||
    !existingUser.twoFactorAuth.totp.enabled
  ) {
    throw new BadRequestError(
      'Authenticator not enabled. Please setup the authenticator first.',
    );
  }

  const secret = await decrypt2FATOTPSecret(
    existingUser.twoFactorAuth.totp.secret,
  );
  const otpMatch = authenticator.verify({ token: otp, secret });
  if (!otpMatch) {
    throw new UnauthorizedError('Incorrect OTP');
  }

  // Filter expired refresh tokens
  existingUser.refreshTokens =
    existingUser.refreshTokens?.filter((rt) => rt.expires > new Date()) || [];
  // Check if device already present
  const existingRefreshToken = existingUser.refreshTokens?.find((rt) =>
    checkSameDevice(config.deviceInfo, rt),
  );
  if (existingRefreshToken) {
    const payload = await generatePayload(existingUser, true);
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

  const payload = await generatePayload(existingUser, true);
  const accessToken = await generateAccessToken(payload);
  const refreshToken = await generateRefreshToken(payload, config.deviceInfo);

  existingUser.refreshTokens.push(refreshToken);
  existingUser.save();

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

const verifyTotpAndLoginHandler: RequestHandler = async (req, res, next) => {
  try {
    const { otp, token } = req.body;
    const { deviceInfo } = res.locals;

    const { user, accessToken, refreshToken } = await loginWithTotp(
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
      .json({ user, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, verifyTotpAndLoginHandler];
