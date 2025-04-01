import * as e from 'express';
import bcrypt from 'bcrypt';
import { AccountChooser, TokenPayload } from '../types/services/auth';
import {
  IRefreshToken,
  IAccount,
  SanitisedAccount,
} from '../types/models/account';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config';
import { IDeviceInfo } from '../types/middlewares/user-agent';
import { decryptCookieValue } from './cookie';
import { InternalServerError, UnauthorizedError } from './errors';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

export async function comparePasswords(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  return bcrypt.compare(password, passwordHash);
}

export async function generatePayload(
  account: IAccount,
  mfaVerified = false,
): Promise<TokenPayload> {
  return {
    accountId: account._id.toString(),
    email: account.email,
    roles: account.roles,
    mfaVerified: mfaVerified,
  };
}

export function generateEmailVerificationToken(payload: TokenPayload): string {
  const uniquePayloadString = JSON.stringify(payload) + Date.now();
  return crypto.createHash('sha256').update(uniquePayloadString).digest('hex');
}

export function excludeSensitiveFields(account: IAccount): SanitisedAccount {
  // Sensitive fields
  delete account.passwordHash;
  delete account.emailVerificationToken;
  delete account.emailVerificationTokenExpires;
  delete account.resetPasswordToken;
  delete account.resetPasswordTokenExpires;
  delete account.refreshTokens;

  // 2FA sensitive fields
  if (account.twoFactorAuth?.otp) {
    account.twoFactorAuth.otp.hash = undefined;
    account.twoFactorAuth.otp.expires = undefined;
  }
  if (account.twoFactorAuth?.totp) {
    account.twoFactorAuth.totp.secret = undefined;
  }
  // Recovery details
  if (account.recoveryDetails) {
    account.recoveryDetails.backupCodesUsedCount =
      account.recoveryDetails.backupCodes.filter((code) => code.usedAt).length;
    account.recoveryDetails.backupCodes = [];
  }
  return account as SanitisedAccount;
}

export async function generate2FAAccessToken(
  payload: TokenPayload,
): Promise<string> {
  return jwt.sign(payload, env.twoFactorAuth.tokenSecret, {
    expiresIn: env.twoFactorAuth.tokenExpiresInSeconds,
  });
}

export async function generateAccessToken(
  payload: TokenPayload,
): Promise<string> {
  return jwt.sign(payload, env.auth.accessTokenSecret, {
    expiresIn: env.auth.accessTokenExpiresInSeconds,
  });
}

export async function verifyAccessToken(
  accessToken: string,
): Promise<TokenPayload> {
  try {
    const payload = jwt.verify(accessToken, env.auth.accessTokenSecret);
    return payload as TokenPayload;
  } catch (_err) {
    throw new UnauthorizedError(
      'Invalid or expired access token. Please login again.',
    );
  }
}

export async function generateRefreshToken(
  payload: TokenPayload,
  deviceInfo: IDeviceInfo,
): Promise<{
  token: string;
  expires: Date;
  deviceInfo?: IDeviceInfo;
}> {
  const uniquePayloadString = JSON.stringify(payload) + Date.now();
  const token = crypto
    .createHash('sha256')
    .update(uniquePayloadString)
    .digest('hex');
  const expires = new Date(
    Date.now() + env.auth.refreshTokenExpiresInSeconds * 1000,
  );

  return { token, expires, deviceInfo };
}

export function checkSameDevice(
  deviceInfo: IDeviceInfo,
  refreshToken: IRefreshToken,
): boolean {
  return (
    (refreshToken.deviceInfo &&
      deviceInfo.browser === refreshToken.deviceInfo.browser &&
      deviceInfo.os === refreshToken.deviceInfo.os &&
      deviceInfo.platform === refreshToken.deviceInfo.platform &&
      deviceInfo.source === refreshToken.deviceInfo.source) ||
    false
  );
}

export async function getAccountChooserCookieValue(
  accountChooserCookie: string,
): Promise<AccountChooser> {
  try {
    const decryptedAccountChooserCookie =
      await decryptCookieValue(accountChooserCookie);
    const accountChooserCookieData = JSON.parse(
      decryptedAccountChooserCookie,
    ) as AccountChooser;
    return accountChooserCookieData;
  } catch (_err) {
    return {
      current: '',
      accounts: [],
    };
  }
}

export async function getAllRefreshTokensMapping(
  req: e.Request,
): Promise<Record<string, string>> {
  const { [env.auth.accountChooserCookieName]: accountChooserCookie } =
    req.cookies;
  const accountChooser =
    await getAccountChooserCookieValue(accountChooserCookie);

  const refreshTokens = accountChooser.accounts.map((account: string) => {
    const { [account]: refreshToken } = req.cookies;
    if (refreshToken) {
      return [account, refreshToken];
    }
    return null;
  });

  const refreshTokensMapping = Object.fromEntries(
    refreshTokens.filter((refreshToken) => refreshToken !== null),
  );
  return refreshTokensMapping;
}

export function generateAccountChooserCookieOptions(): e.CookieOptions {
  return {
    httpOnly: true,
    secure: env.nodeEnv !== 'development',
    sameSite: 'strict',
    path: '/api/v1/auth',
  };
}

export function generateRefreshTokenCookieOptions(): e.CookieOptions {
  return {
    httpOnly: true,
    secure: env.nodeEnv !== 'development',
    sameSite: 'strict',
    path: '/api/v1/auth',
  };
}

export async function generateAccountChooser(
  newRefreshToken: string,
  existingAccountChooser: AccountChooser,
  existingRefreshTokensMapping: Record<string, string>,
): Promise<{
  refreshTokenCookieName: string;
  accountChooser: AccountChooser;
}> {
  const decodedRefreshToken = JSON.parse(
    Buffer.from(newRefreshToken, 'base64').toString('utf-8'),
  ) as IRefreshToken;
  const decodedExistingRefreshTokens = (await Promise.all(
    Object.values(existingRefreshTokensMapping).map((rt) =>
      JSON.parse(Buffer.from(rt, 'base64').toString('utf-8')),
    ),
  )) as IRefreshToken[];
  const existingRefreshToken = decodedExistingRefreshTokens.find(
    (rt) => rt.token === decodedRefreshToken.token,
  );
  const existingRefreshTokenCookieName = Object.keys(
    existingRefreshTokensMapping,
  ).find((key) => existingRefreshTokensMapping[key] === newRefreshToken);

  if (existingRefreshToken && existingRefreshTokenCookieName) {
    return {
      refreshTokenCookieName: existingRefreshTokenCookieName,
      accountChooser: existingAccountChooser,
    };
  }

  const refreshTokenCookieName = `rt_${crypto.randomBytes(8).toString('hex')}`;
  const accountChooser = {
    current: refreshTokenCookieName,
    accounts: [
      ...new Set([
        ...existingAccountChooser.accounts, // existing keys
        refreshTokenCookieName,
      ]),
    ],
  };
  return { refreshTokenCookieName, accountChooser };
}

export async function extractCurrentRefreshToken(
  req: e.Request,
): Promise<[string, string]> {
  const { [env.auth.accountChooserCookieName]: accountChooserCookie } =
    req.cookies;
  const accountChooser =
    await getAccountChooserCookieValue(accountChooserCookie);
  const refreshTokenCookieName = accountChooser.current;
  const { [refreshTokenCookieName]: refreshToken } = req.cookies;
  return [refreshTokenCookieName, refreshToken];
}

export async function removeAccountFromAccountChooser(
  refreshToken: string,
  accountChooser: AccountChooser,
  refreshTokenMapping: Record<string, string>,
): Promise<AccountChooser> {
  const decodedRefreshToken = JSON.parse(
    Buffer.from(refreshToken, 'base64').toString('utf-8'),
  ) as IRefreshToken;
  const decodedRefreshTokens = await Promise.all(
    Object.values(refreshTokenMapping).map((rt) => {
      return JSON.parse(Buffer.from(rt, 'base64').toString('utf-8'));
    }) as IRefreshToken[],
  );
  const existingRefreshToken = decodedRefreshTokens.find(
    (rt) => rt.token === decodedRefreshToken.token,
  );
  const refreshTokenCookieName = Object.keys(refreshTokenMapping).find(
    (key) => refreshTokenMapping[key] === refreshToken,
  );

  if (!existingRefreshToken || !refreshTokenCookieName) {
    return accountChooser;
  }

  const updatedAccounts = accountChooser.accounts.filter(
    (account) => account !== refreshTokenCookieName,
  );

  return { ...accountChooser, accounts: updatedAccounts };
}

export function generateResetPasswordToken(payload: TokenPayload): string {
  const uniquePayloadString = JSON.stringify(payload) + Date.now();
  return crypto.createHash('sha256').update(uniquePayloadString).digest('hex');
}

export async function encryptBackupCode(code: string): Promise<string> {
  const key = env.auth.backupCodeEncryptionSecret;
  if (!key) {
    throw new InternalServerError(
      'Encryption secret for backup code not found',
      false,
    );
  }
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  const iv = Buffer.from(crypto.randomBytes(16));
  const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
  let encrypted = cipher.update(code, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  encrypted = `${iv.toString('hex')}:${encrypted}`;
  return encrypted;
}

export async function decryptBackupCode(
  encryptedCode: string,
): Promise<string> {
  const key = env.auth.backupCodeEncryptionSecret;
  if (!key) {
    throw new InternalServerError(
      'Encryption secret for backup code not found',
      false,
    );
  }
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  let [iv, encrypted]: (string | Buffer)[] = encryptedCode.split(':');
  iv = Buffer.from(iv, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export async function generateBackupCodes(): Promise<string[]> {
  const codes: string[] = [];
  for (let i = 0; i < 10; i++) {
    // 8 characters long
    const code = crypto.randomBytes(4).toString('hex');
    const encryptedCode = await encryptBackupCode(code);
    codes.push(encryptedCode);
  }
  return codes;
}

export async function verify2FAToken(token: string): Promise<TokenPayload> {
  try {
    const payload = jwt.verify(token, env.twoFactorAuth.tokenSecret);
    return payload as TokenPayload;
  } catch (_err) {
    throw new UnauthorizedError(
      'Invalid or expired 2FA token. Please login again.',
    );
  }
}

export async function generateRandomOTP(length = 6): Promise<string> {
  const digits = '0123456789';
  let otp = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, digits.length);
    otp += digits.charAt(randomIndex);
  }

  return otp;
}

export async function encrypt2FATOTPSecret(secret: string): Promise<string> {
  const key = env.twoFactorAuth.totp.encryptionSecret;
  if (!key) {
    throw new InternalServerError(
      'Encryption secret for 2FA TOTP not found',
      false,
    );
  }
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  const iv = Buffer.from(crypto.randomBytes(16));
  const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
  let encrypted = cipher.update(secret, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  encrypted = `${iv.toString('hex')}:${encrypted}`;
  return encrypted;
}

export async function decrypt2FATOTPSecret(
  encryptedSecret: string,
): Promise<string> {
  const key = env.twoFactorAuth.totp.encryptionSecret;
  if (!key) {
    throw new InternalServerError(
      'Encryption secret for 2FA TOTP not found',
      false,
    );
  }
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  let [iv, encrypted]: (string | Buffer)[] = encryptedSecret.split(':');
  iv = Buffer.from(iv, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export async function generateRecoveryEmailVerificationToken(
  payload: TokenPayload & { recoveryEmail: string },
): Promise<string> {
  return jwt.sign(payload, env.auth.recoveryEmailVerificationTokenSecret, {
    expiresIn: env.auth.recoveryEmailVerificationTokenExpiresInSeconds,
  });
}

export async function verifyRecoveryEmailVerificationToken(
  token: string,
): Promise<(TokenPayload & { recoveryEmail: string }) | undefined> {
  try {
    const payload = jwt.verify(
      token,
      env.auth.recoveryEmailVerificationTokenSecret,
    );
    return payload as TokenPayload & { recoveryEmail: string };
  } catch (_err) {
    return undefined;
  }
}
