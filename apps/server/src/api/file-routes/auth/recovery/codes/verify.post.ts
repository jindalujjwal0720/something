import { RequestHandler } from 'express';
import { env } from '../../../../../config';
import {
  checkSameDevice,
  decryptBackupCode,
  excludeSensitiveFields,
  generateAccessToken,
  generateAccountChooser,
  generateAccountChooserCookieOptions,
  generatePayload,
  generateRefreshToken,
  generateRefreshTokenCookieOptions,
  getAccountChooserCookieValue,
  getAllRefreshTokensMapping,
  verifyRecoveryEmailVerificationToken,
} from '../../../../../utils/auth';
import { encryptCookieValue } from '../../../../../utils/cookie';
import { IAccount } from '../../../../../types/models/account';
import Account from '../../../../../models/account';
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
} from '../../../../../utils/errors';
import { AuthenticationEvent } from '../../../../../events/auth/events';
import { EventBus } from '../../../../../events/bus';
import { celebrate, Joi, Segments } from 'celebrate';
import { IDeviceInfo } from '../../../../../types/middlewares/user-agent';
import User from '../../../../../models/user';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    token: Joi.string().required(),
    code: Joi.string().required(),
  }),
});

async function loginWithRecoveryCode(
  recoveryLoginData: { code: string; token: string },
  config: { deviceInfo: IDeviceInfo },
): Promise<{
  account: IAccount;
  accessToken: string;
  refreshToken: string;
}> {
  const { token, code: recoveryCode } = recoveryLoginData;
  const payload = await verifyRecoveryEmailVerificationToken(token);
  if (!payload) {
    throw new UnauthorizedError(
      'Invalid or expired recovery email verification token',
    );
  }

  const account = await Account.findOne({ email: payload.email }).select(
    '+recoveryDetails +refreshTokens',
  );
  if (!account) {
    throw new NotFoundError('User not found');
  }

  if (
    !account.recoveryDetails?.backupCodes ||
    account.recoveryDetails?.backupCodes.length === 0
  ) {
    throw new BadRequestError(
      'No recovery codes found. Please generate new recovery codes',
    );
  }

  const decryptedBackupCodes = await Promise.all(
    account.recoveryDetails.backupCodes.map((bc) => decryptBackupCode(bc.code)),
  );
  const backupCodeIndex = decryptedBackupCodes.findIndex(
    (code) => code === recoveryCode,
  );
  if (
    backupCodeIndex === -1 ||
    account.recoveryDetails.backupCodes[backupCodeIndex].usedAt
  ) {
    throw new UnauthorizedError('Invalid or expired recovery code');
  }

  // mark the recovery code as used with a timestamp
  account.recoveryDetails.backupCodes[backupCodeIndex].usedAt = new Date();

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

  const newRefreshToken = await generateRefreshToken(
    payload,
    config.deviceInfo,
  );

  account.refreshTokens.push(newRefreshToken);
  await account.save();

  const sanitisedAccount = excludeSensitiveFields(account.toObject());

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) throw new NotFoundError('User not found');

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.LOGGED_IN, {
    user: { name: user.name, email: sanitisedAccount.email },
    deviceInfo: config.deviceInfo,
  });

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(newRefreshToken),
  ).toString('base64');
  return {
    account: sanitisedAccount,
    accessToken: '',
    refreshToken: encodedRefreshToken,
  };
}

const verifyRecoveryCodeAndLoginHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const { code: recoveryCode, token } = req.body;
    const { deviceInfo } = res.locals;

    const { account, accessToken, refreshToken } = await loginWithRecoveryCode(
      { code: recoveryCode, token },
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

export default [validatorMiddleware, verifyRecoveryCodeAndLoginHandler];
