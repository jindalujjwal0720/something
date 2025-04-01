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
import Account from '../../../models/account';
import { IAccount } from '../../../types/models/account';
// import { AuthenticationEvent } from '../../../events/auth/events';
// import { EventBus } from '../../../events/bus';
import { extractIpInfo } from '../../middlewares/user-agent';
import { IDeviceInfo } from '../../../types/middlewares/user-agent';

async function refreshTokens(
  refreshToken: string,
  { deviceInfo }: { deviceInfo: IDeviceInfo },
): Promise<{ account: IAccount; accessToken: string; refreshToken: string }> {
  const decodedRefreshToken = JSON.parse(
    Buffer.from(refreshToken, 'base64').toString('utf-8'),
  );
  const account = await Account.findOne({
    refreshTokens: { $elemMatch: { token: decodedRefreshToken.token } },
  }).select('+refreshTokens');
  if (!account) {
    throw new UnauthorizedError('Invalid refresh token');
  }

  const refreshTokenIndex = account.refreshTokens?.findIndex(
    (rt) => rt.token === decodedRefreshToken.token,
  );
  if (refreshTokenIndex === undefined || refreshTokenIndex === -1) {
    throw new UnauthorizedError('Invalid refresh token');
  }

  const refreshTokenObject = account.refreshTokens?.[refreshTokenIndex];
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

  const payload = await generatePayload(account);
  const accessToken = await generateAccessToken(payload);
  const newRefreshToken = await generateRefreshToken(payload, deviceInfo);

  account.refreshTokens?.splice(refreshTokenIndex, 1);
  account.refreshTokens?.push(newRefreshToken);
  await account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(newRefreshToken),
  ).toString('base64');
  return {
    account: sanitisedAccount,
    accessToken,
    refreshToken: encodedRefreshToken,
  };
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
    const { deviceInfo } = res.locals;
    const {
      account,
      accessToken,
      refreshToken: newRefreshToken,
    } = await refreshTokens(refreshToken, { deviceInfo });

    res
      .status(200)
      .cookie(
        refreshTokenCookieName,
        newRefreshToken,
        generateRefreshTokenCookieOptions(),
      )
      .json({ account, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [extractIpInfo, refreshHandler];
