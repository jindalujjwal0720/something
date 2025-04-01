import { RequestHandler } from 'express';
import { env } from '../../../config';
import {
  // checkSameDevice,
  excludeSensitiveFields,
  generateAccessToken,
  generatePayload,
  generateRefreshToken,
  generateRefreshTokenCookieOptions,
  getAccountChooserCookieValue,
} from '../../../utils/auth';
import { UnauthorizedError } from '../../../utils/errors';
import { UserRefreshTokensConfig } from '../../../types/services/auth';
import User from '../../../models/user';
import { IUser } from '../../../types/models/user';
// import { AuthenticationEvent } from '../../../events/auth/events';
// import { EventBus } from '../../../events/bus';
import { extractIpInfo } from '../../middlewares/user-agent';

async function refreshTokens(
  refreshToken: string,
  { deviceInfo, ipInfo: _ }: UserRefreshTokensConfig,
): Promise<{ user: IUser; accessToken: string; refreshToken: string }> {
  const decodedRefreshToken = JSON.parse(
    Buffer.from(refreshToken, 'base64').toString('utf-8'),
  );
  const existingUser = await User.findOne({
    refreshTokens: { $elemMatch: { token: decodedRefreshToken.token } },
  }).select('+refreshTokens');
  if (!existingUser) {
    throw new UnauthorizedError('Invalid refresh token');
  }

  const refreshTokenIndex = existingUser.refreshTokens?.findIndex(
    (rt) => rt.token === decodedRefreshToken.token,
  );
  if (refreshTokenIndex === undefined || refreshTokenIndex === -1) {
    throw new UnauthorizedError('Invalid refresh token');
  }

  const refreshTokenObject = existingUser.refreshTokens?.[refreshTokenIndex];
  if (!refreshTokenObject || refreshTokenObject.expires < new Date()) {
    throw new UnauthorizedError('Refresh token expired');
  }

  // TODO: This part needs to be checked
  // TODO: This is emiting falsely event for force logout
  // if (!checkSameDevice(deviceInfo, refreshTokenObject)) {
  //   // Sign out from all devices
  //   existingUser.refreshTokens = [];
  //   await existingUser.save();

  //   // Publish events for force logout
  //   EventBus.auth.emit(AuthenticationEvent.FORCE_LOGGED_OUT, {
  //     user: { name: existingUser.name, email: existingUser.email },
  //     deviceInfo,
  //     ipInfo,
  //   });

  //   throw new UnauthorizedError(
  //     'Device mismatch. Logged out from all devices.',
  //   );
  // }

  const payload = await generatePayload(existingUser);
  const accessToken = await generateAccessToken(payload);
  const newRefreshToken = await generateRefreshToken(payload, deviceInfo);

  existingUser.refreshTokens?.splice(refreshTokenIndex, 1);
  existingUser.refreshTokens?.push(newRefreshToken);
  await existingUser.save();

  const userObject = excludeSensitiveFields(existingUser.toObject());

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(newRefreshToken),
  ).toString('base64');
  return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
}

const refreshHandler: RequestHandler = async (req, res, next) => {
  try {
    const { [env.auth.accountChooserCookieName]: accountChooserCookie } =
      req.cookies;
    const accountChooser =
      await getAccountChooserCookieValue(accountChooserCookie);
    const refreshTokenCookieName = accountChooser.current;

    const { [refreshTokenCookieName]: refreshToken } = req.cookies;
    if (!refreshToken) {
      throw new UnauthorizedError('Refresh token is missing');
    }
    const { deviceInfo, ipInfo } = res.locals;
    const {
      user,
      accessToken,
      refreshToken: newRefreshToken,
    } = await refreshTokens(refreshToken, {
      deviceInfo,
      ipInfo,
    });

    res
      .status(200)
      .cookie(
        refreshTokenCookieName,
        newRefreshToken,
        generateRefreshTokenCookieOptions(),
      )
      .json({ user, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [extractIpInfo, refreshHandler];
