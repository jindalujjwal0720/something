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
import {
  UserLoginConfig,
  UserRecoveryCodeLoginDTO,
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
    code: Joi.string().required(),
  }),
});

async function loginWithRecoveryCode(
  userDTO: UserRecoveryCodeLoginDTO,
  config: UserLoginConfig,
): Promise<{
  user: IUser;
  accessToken: string;
  refreshToken: string;
}> {
  const { token, code: recoveryCode } = userDTO;
  const payload = await verifyRecoveryEmailVerificationToken(token);
  if (!payload) {
    throw new UnauthorizedError(
      'Invalid or expired recovery email verification token',
    );
  }

  const existingUser = await User.findOne({ email: payload.email }).select(
    '+recoveryDetails +refreshTokens',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  if (
    !existingUser.recoveryDetails?.backupCodes ||
    existingUser.recoveryDetails?.backupCodes.length === 0
  ) {
    throw new BadRequestError(
      'No recovery codes found. Please generate new recovery codes',
    );
  }

  const decryptedBackupCodes = await Promise.all(
    existingUser.recoveryDetails.backupCodes.map((bc) =>
      decryptBackupCode(bc.code),
    ),
  );
  const backupCodeIndex = decryptedBackupCodes.findIndex(
    (code) => code === recoveryCode,
  );
  if (
    backupCodeIndex === -1 ||
    existingUser.recoveryDetails.backupCodes[backupCodeIndex].usedAt
  ) {
    throw new UnauthorizedError('Invalid or expired recovery code');
  }

  // mark the recovery code as used with a timestamp
  existingUser.recoveryDetails.backupCodes[backupCodeIndex].usedAt = new Date();

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

  const newRefreshToken = await generateRefreshToken(
    payload,
    config.deviceInfo,
  );

  existingUser.refreshTokens.push(newRefreshToken);
  await existingUser.save();

  const userObject = excludeSensitiveFields(existingUser.toObject());

  // Publish events
  EventBus.auth.emit(AuthenticationEvent.LOGGED_IN, {
    user: { name: userObject.name, email: userObject.email },
    deviceInfo: config.deviceInfo,
  });

  const encodedRefreshToken = Buffer.from(
    JSON.stringify(newRefreshToken),
  ).toString('base64');
  return {
    user: userObject,
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

    const { user, accessToken, refreshToken } = await loginWithRecoveryCode(
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
      .json({ user, token: accessToken });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, verifyRecoveryCodeAndLoginHandler];
