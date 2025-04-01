import { RequestHandler } from 'express';
import { UnauthorizedError } from '../../../utils/errors';
import {
  extractCurrentRefreshToken,
  generateAccountChooserCookieOptions,
  generateRefreshTokenCookieOptions,
  getAccountChooserCookieValue,
  getAllRefreshTokensMapping,
  removeAccountFromAccountChooser,
} from '../../../utils/auth';
import { encryptCookieValue } from '../../../utils/cookie';
import { env } from '../../../config';
import Account from '../../../models/account';

async function logout(refreshToken: string): Promise<void> {
  const decodedRefreshToken = JSON.parse(
    Buffer.from(refreshToken, 'base64').toString('utf-8'),
  );
  const account = await Account.findOne({
    refreshTokens: { $elemMatch: { token: decodedRefreshToken.token } },
  });
  if (!account) {
    // return silently if token not found
    return;
  }

  account.refreshTokens = account.refreshTokens?.filter(
    (rt) => rt.token !== decodedRefreshToken.token,
  );
  await account.save();
}

const logoutHandler: RequestHandler = async (req, res, next) => {
  try {
    const [refreshTokenCookieName, refreshToken] =
      await extractCurrentRefreshToken(req);
    if (!refreshToken) {
      throw new UnauthorizedError('Refresh token is missing');
    }

    await logout(refreshToken);
    const {
      [env.auth.accountChooserCookieName]: existingAccountChooserCookie,
    } = req.cookies;

    const existingAccountChooser = await getAccountChooserCookieValue(
      existingAccountChooserCookie,
    );
    const refreshTokensMapping = await getAllRefreshTokensMapping(req);
    const accountChooser = await removeAccountFromAccountChooser(
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
      .clearCookie(refreshTokenCookieName, generateRefreshTokenCookieOptions())
      .json({ message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
};

export default logoutHandler;
