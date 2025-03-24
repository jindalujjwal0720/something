import { RequestHandler } from 'express';
import { IDeviceInfo } from '../../../../../types/middlewares/user-agent';
import { env } from '../../../../../config';
import {
  checkSameDevice,
  comparePasswords,
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
import User from '../../../../../models/user';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { EventBus } from '../../../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
    otp: Joi.string().required(),
  }),
});

async function loginWithOtp(
  userDTO: UserOTPLoginDTO,
  config: UserLoginConfig,
): Promise<{
  user: IUser;
  accessToken: string;
  refreshToken: string;
}> {
  const { token } = userDTO;
  const twoFactorAuthPayload = await verify2FAToken(token);

  const existingUser = await User.findOne({
    email: twoFactorAuthPayload.email,
  }).select('+twoFactorAuth +refreshTokens');
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (
    !existingUser.twoFactorAuth?.enabled ||
    !existingUser.twoFactorAuth.otp.enabled
  ) {
    throw new BadRequestError('OTP based 2FA not enabled for this user');
  }

  if (
    !existingUser.twoFactorAuth.otp.hash ||
    !existingUser.twoFactorAuth.otp.expires
  ) {
    throw new BadRequestError('OTP not generated. Please request a new OTP');
  }

  const otpMatch = await comparePasswords(
    userDTO.otp,
    existingUser.twoFactorAuth.otp.hash || '',
  );
  if (!otpMatch) {
    throw new UnauthorizedError('Incorrect OTP');
  }

  if (
    existingUser.twoFactorAuth.otp.expires &&
    existingUser.twoFactorAuth.otp.expires < new Date()
  ) {
    existingUser.twoFactorAuth.otp.hash = undefined;
    existingUser.twoFactorAuth.otp.expires = undefined;
    await existingUser.save();

    throw new UnauthorizedError('OTP has expired');
  }

  // Filter expired refresh tokens
  existingUser.refreshTokens = existingUser.refreshTokens?.filter(
    (rt) => rt.expires > new Date(),
  );
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

  existingUser.refreshTokens?.push(refreshToken);
  existingUser.twoFactorAuth.otp.hash = undefined;
  existingUser.twoFactorAuth.otp.expires = undefined;
  existingUser.isEmailVerified = true; // Email verified on OTP login
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

const verifyOtpAndLoginHandler: RequestHandler = async (req, res, next) => {
  try {
    const { otp, token } = req.body;
    const { useragent } = res.locals;
    const deviceInfo: IDeviceInfo = {
      browser: useragent?.browser || 'unknown',
      os: useragent?.os || 'unknown',
      platform: useragent?.platform || 'unknown',
      source: useragent?.source || 'unknown',
    };

    const { user, accessToken, refreshToken } = await loginWithOtp(
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

export const handler = [validatorMiddleware, verifyOtpAndLoginHandler];
