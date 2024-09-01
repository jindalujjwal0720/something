import { Model } from 'mongoose';
import { IRefreshToken, IUser } from '../types/models/user.d';
import { IDeviceInfo } from '../types/middlewares/user-agent';
import bcrypt from 'bcrypt';
import { AppError, CommonErrors } from '../utils/errors';
import jwt from 'jsonwebtoken';
import { env, meta } from '../config';
import crypto from 'crypto';
import { EventsPublisher } from '../events';
import {
  AccountChooser,
  Disable2FAConfig,
  Disable2FADTO,
  Enable2FAConfig,
  Enable2FADTO,
  RequestPasswordResetDTO,
  ResetPasswordConfig,
  ResetPasswordDTO,
  Setup2FAAuthenticatorDTO,
  TokenPayload,
  UserLoginConfig,
  UserLoginDTO,
  UserLoginResponse,
  UserOTPLoginDTO,
  UserRefreshTokensConfig,
  UserRegisterDTO,
} from '../types/services/auth.d';
import { authenticator } from 'otplib';

export class AuthService {
  private userModel: Model<IUser>;
  private publisher: EventsPublisher;

  constructor(userModel: Model<IUser>, publisher: EventsPublisher) {
    this.userModel = userModel;
    this.publisher = publisher;
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  private async comparePasswords(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  private async generatePayload(user: IUser): Promise<TokenPayload> {
    return {
      email: user.email,
      name: user.name,
      imageUrl: user.imageUrl,
      roles: user.roles,
    };
  }

  private async generateAccessToken(payload: TokenPayload): Promise<string> {
    return jwt.sign(payload, env.auth.accessTokenSecret, {
      expiresIn: env.auth.accessTokenExpiresInSeconds,
    });
  }

  private async generateRefreshToken(
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

  private async generateRandomOTP(length = 6): Promise<string> {
    const digits = '0123456789';
    let otp = '';

    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, digits.length);
      otp += digits.charAt(randomIndex);
    }

    return otp;
  }

  private async filterExpiredRefreshTokens(
    refreshTokens: IRefreshToken[],
  ): Promise<IRefreshToken[]> {
    return refreshTokens.filter((rt) => rt.expires > new Date());
  }

  private excludeSensitiveFields(user: IUser): IUser {
    // Sensitive fields
    delete user.passwordHash;
    delete user.emailVerificationToken;
    delete user.emailVerificationTokenExpires;
    delete user.resetPasswordToken;
    delete user.resetPasswordTokenExpires;
    delete user.refreshTokens;

    // 2FA sensitive fields
    if (user.twoFactorAuth?.otp) {
      user.twoFactorAuth.otp.hash = undefined;
      user.twoFactorAuth.otp.expires = undefined;
    }
    if (user.twoFactorAuth?.totp) {
      user.twoFactorAuth.totp.secret = undefined;
    }
    return user;
  }

  private async encodeRefreshToken(
    refreshToken: IRefreshToken,
  ): Promise<string> {
    // Encode the refresh token just to make it easy to store
    // No need to encrypt as it won't add any more security
    return Buffer.from(JSON.stringify(refreshToken)).toString('base64');
  }

  private async decodeRefreshToken(token: string): Promise<IRefreshToken> {
    return JSON.parse(Buffer.from(token, 'base64').toString());
  }

  private checkSameDevice(
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

  private generateResetPasswordToken(payload: TokenPayload): string {
    const uniquePayloadString = JSON.stringify(payload) + Date.now();
    return crypto
      .createHash('sha256')
      .update(uniquePayloadString)
      .digest('hex');
  }

  private generateEmailVerificationToken(payload: TokenPayload): string {
    const uniquePayloadString = JSON.stringify(payload) + Date.now();
    return crypto
      .createHash('sha256')
      .update(uniquePayloadString)
      .digest('hex');
  }

  private async generate2FAAccessToken(payload: TokenPayload): Promise<string> {
    return jwt.sign(payload, env.twoFactorAuth.tokenSecret, {
      expiresIn: env.twoFactorAuth.tokenExpiresInSeconds,
    });
  }

  private async verify2FAToken(token: string): Promise<TokenPayload> {
    try {
      const payload = jwt.verify(token, env.twoFactorAuth.tokenSecret);
      return payload as TokenPayload;
    } catch (_err) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Invalid or expired 2FA token. Please login again.',
      );
    }
  }

  private async encrypt2FATOTPSecret(secret: string): Promise<string> {
    const key = env.twoFactorAuth.totp.encryptionSecret;
    if (!key) {
      throw new AppError(
        CommonErrors.InternalServerError.name,
        CommonErrors.InternalServerError.statusCode,
        'Encryption secret for 2FA TOTP not found',
        false,
      );
    }
    const derivedKey = crypto.scryptSync(key, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    encrypted = `${iv.toString('hex')}:${encrypted}`;
    return encrypted;
  }

  private async decrypt2FATOTPSecret(encryptedSecret: string): Promise<string> {
    const key = env.twoFactorAuth.totp.encryptionSecret;
    if (!key) {
      throw new AppError(
        CommonErrors.InternalServerError.name,
        CommonErrors.InternalServerError.statusCode,
        'Encryption secret for 2FA TOTP not found',
        false,
      );
    }
    const derivedKey = crypto.scryptSync(key, 'salt', 32);
    const [iv, encrypted] = encryptedSecret.split(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  public async register(userDTO: UserRegisterDTO): Promise<{ user: IUser }> {
    const existingUser = await this.userModel.findOne({
      email: userDTO.email,
    });
    if (existingUser) {
      throw new AppError(
        CommonErrors.Conflict.name,
        CommonErrors.Conflict.statusCode,
        'User with this email already exists. Please login instead.',
      );
    }

    const hashedPassword = await this.hashPassword(userDTO.password);
    const createdUser = new this.userModel({
      ...userDTO,
      password: undefined,
      passwordHash: hashedPassword,
      role: 'user',
    });

    const payload = await this.generatePayload(createdUser);
    createdUser.emailVerificationToken =
      this.generateEmailVerificationToken(payload);
    createdUser.emailVerificationTokenExpires = new Date(
      Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
    );
    await createdUser.save();

    const user = this.excludeSensitiveFields(createdUser.toObject());

    // Publish events
    this.publisher.auth.publishUserEmailVerificationRequestedEvent({
      user,
      emailVerificationToken: createdUser.emailVerificationToken,
    });
    this.publisher.auth.publishUserRegisteredEvent({ user });

    return { user };
  }

  public async verifyEmail(token: string): Promise<void> {
    const existingUser = await this.userModel
      .findOne({
        emailVerificationToken: token,
      })
      .select('+emailVerificationToken +emailVerificationTokenExpires');

    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'Invalid or expired email verification token',
      );
    }

    if (
      !existingUser.emailVerificationTokenExpires ||
      existingUser.emailVerificationTokenExpires < new Date()
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Email verification token expired. Please request a new one by logging in.',
      );
    }

    existingUser.emailVerificationToken = undefined;
    existingUser.emailVerificationTokenExpires = undefined;
    existingUser.isEmailVerified = true;
    await existingUser.save();
  }

  public async resendEmailVerification(email: string): Promise<void> {
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+emailVerificationToken +emailVerificationTokenExpires');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (existingUser.isEmailVerified) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Email already verified',
      );
    }

    if (
      existingUser.emailVerificationTokenExpires &&
      existingUser.emailVerificationTokenExpires > new Date()
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Email verification token already sent.',
      );
    }

    const payload = await this.generatePayload(existingUser);
    existingUser.emailVerificationToken =
      this.generateEmailVerificationToken(payload);
    existingUser.emailVerificationTokenExpires = new Date(
      Date.now() + env.auth.emailVerificationTokenExpiresInSeconds * 1000,
    );
    await existingUser.save();

    const user = this.excludeSensitiveFields(existingUser.toObject());

    // Publish events
    this.publisher.auth.publishUserEmailVerificationRequestedEvent({
      user,
      emailVerificationToken: existingUser.emailVerificationToken,
    });

    return;
  }

  public async loginWithEmailAndPassword(
    userDTO: UserLoginDTO,
    config: UserLoginConfig,
  ): Promise<UserLoginResponse> {
    const existingUser = await this.userModel
      .findOne({ email: userDTO.email })
      .select('+passwordHash +refreshTokens +twoFactorAuth');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      userDTO.password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    if (!existingUser.isEmailVerified) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Email not verified. If you did not receive the verification email, please request a new one.',
      );
    }

    // Filter expired refresh tokens
    existingUser.refreshTokens = await this.filterExpiredRefreshTokens(
      existingUser.refreshTokens || [],
    );
    // Check if device already present
    const existingRefreshToken = existingUser.refreshTokens?.find((rt) =>
      this.checkSameDevice(config.deviceInfo, rt),
    );
    if (existingRefreshToken) {
      const payload = await this.generatePayload(existingUser);
      const accessToken = await this.generateAccessToken(payload);
      const encodedRefreshToken =
        await this.encodeRefreshToken(existingRefreshToken);

      const userObject = this.excludeSensitiveFields(existingUser.toObject());
      return {
        user: userObject,
        accessToken,
        refreshToken: encodedRefreshToken,
      };
    }

    // if 2FA is enabled
    // send a short access token to be used for getting user's details
    if (existingUser.twoFactorAuth?.enabled) {
      const payload = await this.generatePayload(existingUser);
      const token = await this.generate2FAAccessToken(payload);
      return { requires2FA: true, token };
    }

    const payload = await this.generatePayload(existingUser);
    const accessToken = await this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(
      payload,
      config.deviceInfo,
    );

    existingUser.refreshTokens.push(refreshToken);
    await existingUser.save();

    const userObject = this.excludeSensitiveFields(existingUser.toObject());

    // Publish events
    this.publisher.auth.publishUserLoggedInEvent({
      user: { name: userObject.name, email: userObject.email },
      deviceInfo: config.deviceInfo,
    });

    const encodedRefreshToken = await this.encodeRefreshToken(refreshToken);
    return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
  }

  public async logout(refreshToken: string): Promise<void> {
    const decodedRefreshToken = await this.decodeRefreshToken(refreshToken);
    const existingUser = await this.userModel.findOne({
      refreshTokens: { $elemMatch: { token: decodedRefreshToken.token } },
    });
    if (!existingUser) {
      // return silently if token not found
      return;
    }

    existingUser.refreshTokens = existingUser.refreshTokens?.filter(
      (rt) => rt.token !== decodedRefreshToken.token,
    );
    await existingUser.save();
  }

  public async logoutAllDevices(email: string): Promise<void> {
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+refreshTokens');
    if (!existingUser) {
      // return silently if user not found
      return;
    }

    existingUser.refreshTokens = [];
    await existingUser.save();
  }

  public async verifyAccessToken(accessToken: string): Promise<TokenPayload> {
    try {
      const payload = jwt.verify(accessToken, env.auth.accessTokenSecret);
      return payload as TokenPayload;
    } catch (_err) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Invalid or expired access token. Please login again.',
      );
    }
  }

  public async refreshTokens(
    refreshToken: string,
    { deviceInfo, ipInfo }: UserRefreshTokensConfig,
  ): Promise<{ user: IUser; accessToken: string; refreshToken: string }> {
    const decodedRefreshToken = await this.decodeRefreshToken(refreshToken);
    const existingUser = await this.userModel
      .findOne({
        refreshTokens: { $elemMatch: { token: decodedRefreshToken.token } },
      })
      .select('+refreshTokens');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Invalid refresh token',
      );
    }

    const refreshTokenIndex = existingUser.refreshTokens?.findIndex(
      (rt) => rt.token === decodedRefreshToken.token,
    );
    if (refreshTokenIndex === undefined || refreshTokenIndex === -1) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Invalid refresh token',
      );
    }

    const refreshTokenObject = existingUser.refreshTokens?.[refreshTokenIndex];
    if (!refreshTokenObject || refreshTokenObject.expires < new Date()) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Refresh token expired',
      );
    }

    if (!this.checkSameDevice(deviceInfo, refreshTokenObject)) {
      // Sign out from all devices
      existingUser.refreshTokens = [];
      await existingUser.save();

      // Publish events for force logout
      this.publisher.auth.publishUserForceLoggedOutEvent({
        user: { name: existingUser.name, email: existingUser.email },
        deviceInfo,
        ipInfo,
      });

      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Device mismatch. Logged out from all devices.',
      );
    }

    const payload = await this.generatePayload(existingUser);
    const accessToken = await this.generateAccessToken(payload);
    const newRefreshToken = await this.generateRefreshToken(
      payload,
      deviceInfo,
    );

    existingUser.refreshTokens?.splice(refreshTokenIndex, 1);
    existingUser.refreshTokens?.push(newRefreshToken);
    await existingUser.save();

    const userObject = this.excludeSensitiveFields(existingUser.toObject());

    const encodedRefreshToken = await this.encodeRefreshToken(newRefreshToken);
    return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
  }

  public async requestPasswordReset(data: RequestPasswordResetDTO) {
    const existingUser = await this.userModel
      .findOne({
        email: data.email,
      })
      .select('+refreshTokens +resetPasswordToken +resetPasswordTokenExpires');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    const payload = await this.generatePayload(existingUser);
    const resetPasswordToken = this.generateResetPasswordToken(payload);
    existingUser.resetPasswordToken = resetPasswordToken;
    existingUser.resetPasswordTokenExpires = new Date(
      Date.now() + env.auth.resetPasswordTokenExpiresInSeconds * 1000,
    );
    if (data.logoutAllDevices) {
      existingUser.refreshTokens = [];
    }
    await existingUser.save();

    // Publish events
    this.publisher.auth.publishUserPasswordChangeRequestedEvent({
      user: { name: existingUser.name, email: existingUser.email },
      resetPasswordToken,
    });
  }

  public async resetPassword(
    data: ResetPasswordDTO,
    config: ResetPasswordConfig,
  ): Promise<void> {
    const existingUser = await this.userModel
      .findOne({ email: data.user.email })
      .select('+passwordHash +resetPasswordToken +resetPasswordTokenExpires');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    // will be true if token is valid and not expired
    let isTokenValid =
      existingUser.resetPasswordToken === data.user.currentPasswordOrToken &&
      existingUser.resetPasswordTokenExpires &&
      existingUser.resetPasswordTokenExpires > new Date();

    // check if it's the current password
    const passwordsMatch = await this.comparePasswords(
      data.user.currentPasswordOrToken,
      existingUser.passwordHash || '',
    );

    if (!isTokenValid && !passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Your current password or token is incorrect',
      );
    }

    // don't allow to reset password with the same password
    if (
      await this.comparePasswords(
        data.user.newPassword,
        existingUser.passwordHash || '',
      )
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'New password cannot be the same as the current password',
      );
    }

    const hashedPassword = await this.hashPassword(data.user.newPassword);
    existingUser.passwordHash = hashedPassword;
    // logout all devices if requested
    if (data.logoutAllDevices) {
      existingUser.refreshTokens = [];
    }
    existingUser.resetPasswordToken = undefined;
    existingUser.resetPasswordTokenExpires = undefined;
    await existingUser.save();

    // Publish events
    this.publisher.auth.publishUserPasswordChangedEvent({
      user: { name: existingUser.name, email: existingUser.email },
      deviceInfo: config.deviceInfo,
      ipInfo: config.ipInfo,
    });
  }

  public async generateAccountChooser(
    newRefreshToken: string,
    existingAccountChooser: AccountChooser,
    existingRefreshTokensMapping: Record<string, string>,
  ): Promise<{
    refreshTokenCookieName: string;
    accountChooser: AccountChooser;
  }> {
    const decodedRefreshToken = await this.decodeRefreshToken(newRefreshToken);
    const decodedExistingRefreshTokens = await Promise.all(
      Object.values(existingRefreshTokensMapping).map(this.decodeRefreshToken),
    );
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

  public async removeAccountFromAccountChooser(
    refreshToken: string,
    accountChooser: AccountChooser,
    refreshTokenMapping: Record<string, string>,
  ): Promise<AccountChooser> {
    const decodedRefreshToken = await this.decodeRefreshToken(refreshToken);
    const decodedRefreshTokens = await Promise.all(
      Object.values(refreshTokenMapping).map(this.decodeRefreshToken),
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

  public async enable2FA(
    userDTO: Enable2FADTO,
    config: Enable2FAConfig,
  ): Promise<void> {
    const { email, password } = userDTO;
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +passwordHash');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA already enabled for the user',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    existingUser.twoFactorAuth = {
      enabled: true,
      otp: { enabled: true }, // OTP based 2FA enabled by default
      totp: { enabled: false },
    };
    await existingUser.save();

    // Publish events
    this.publisher.auth.publishUser2FAEnabledEvent({
      user: { name: existingUser.name, email: existingUser.email },
      deviceInfo: config.deviceInfo,
      ipInfo: config.ipInfo,
    });
  }

  public async disable2FA(
    userDTO: Disable2FADTO,
    config: Disable2FAConfig,
  ): Promise<void> {
    const { email, password } = userDTO;
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +passwordHash');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (!existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA not enabled for the user',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    existingUser.twoFactorAuth = undefined;
    await existingUser.save();

    // Publish events
    this.publisher.auth.publishUser2FADisabledEvent({
      user: { name: existingUser.name, email: existingUser.email },
      deviceInfo: config.deviceInfo,
      ipInfo: config.ipInfo,
    });
  }

  public async get2faLoginMethods(token: string): Promise<string[]> {
    const { email } = await this.verify2FAToken(token);

    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (!existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA not enabled for the user',
      );
    }

    const methods: string[] = ['otp']; // OTP based 2FA enabled by default
    methods.push('recovery'); // Recovery codes are always available
    if (existingUser.twoFactorAuth.totp?.enabled) {
      methods.push('totp');
    }

    return methods;
  }

  public async loginWith2FAOTP(
    userDTO: UserOTPLoginDTO,
    config: UserLoginConfig,
  ): Promise<{
    user: IUser;
    accessToken: string;
    refreshToken: string;
  }> {
    const { token } = userDTO;
    const twoFactorAuthPayload = await this.verify2FAToken(token);

    const existingUser = await this.userModel
      .findOne({ email: twoFactorAuthPayload.email })
      .select('+twoFactorAuth +refreshTokens');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (
      !existingUser.twoFactorAuth?.enabled ||
      !existingUser.twoFactorAuth.otp.enabled
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'OTP based 2FA not enabled for this user',
      );
    }

    if (
      !existingUser.twoFactorAuth.otp.hash ||
      !existingUser.twoFactorAuth.otp.expires
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'OTP not generated. Please request a new OTP',
      );
    }

    const otpMatch = await this.comparePasswords(
      userDTO.otp,
      existingUser.twoFactorAuth.otp.hash || '',
    );
    if (!otpMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect OTP',
      );
    }

    if (
      existingUser.twoFactorAuth.otp.expires &&
      existingUser.twoFactorAuth.otp.expires < new Date()
    ) {
      existingUser.twoFactorAuth.otp.hash = undefined;
      existingUser.twoFactorAuth.otp.expires = undefined;
      await existingUser.save();

      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'OTP has expired',
      );
    }

    // Filter expired refresh tokens
    existingUser.refreshTokens = await this.filterExpiredRefreshTokens(
      existingUser.refreshTokens || [],
    );
    // Check if device already present
    const existingRefreshToken = existingUser.refreshTokens?.find((rt) =>
      this.checkSameDevice(config.deviceInfo, rt),
    );
    if (existingRefreshToken) {
      const payload = await this.generatePayload(existingUser);
      const accessToken = await this.generateAccessToken(payload);
      const encodedRefreshToken =
        await this.encodeRefreshToken(existingRefreshToken);

      const userObject = this.excludeSensitiveFields(existingUser.toObject());
      return {
        user: userObject,
        accessToken,
        refreshToken: encodedRefreshToken,
      };
    }

    const payload = await this.generatePayload(existingUser);
    const accessToken = await this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(
      payload,
      config.deviceInfo,
    );

    existingUser.refreshTokens.push(refreshToken);
    existingUser.twoFactorAuth.otp.hash = undefined;
    existingUser.twoFactorAuth.otp.expires = undefined;
    existingUser.isEmailVerified = true; // Email verified on OTP login
    await existingUser.save();

    const userObject = this.excludeSensitiveFields(existingUser.toObject());

    // Publish events
    this.publisher.auth.publishUserLoggedInEvent({
      user: { name: userObject.name, email: userObject.email },
      deviceInfo: config.deviceInfo,
    });

    const encodedRefreshToken = await this.encodeRefreshToken(refreshToken);
    return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
  }

  public async send2FALoginOTP(token: string): Promise<{ expires: Date }> {
    const { email } = await this.verify2FAToken(token);

    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (
      !existingUser.twoFactorAuth?.enabled ||
      !existingUser.twoFactorAuth.otp.enabled
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'OTP based 2FA not enabled for this user',
      );
    }

    if (
      existingUser.twoFactorAuth.otp.expires &&
      existingUser.twoFactorAuth.otp.expires > new Date()
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'You already have an active OTP. Please wait for it to expire.',
      );
    }

    const otp = await this.generateRandomOTP();
    existingUser.twoFactorAuth.otp.hash = await this.hashPassword(otp);
    existingUser.twoFactorAuth.otp.expires = new Date(
      Date.now() + env.twoFactorAuth.otp.expiresInSeconds * 1000,
    );
    await existingUser.save();

    const user = this.excludeSensitiveFields(existingUser.toObject());

    // Publish events
    this.publisher.auth.publishUser2faOtpGeneratedEvent({
      user,
      otp,
    });

    return { expires: existingUser.twoFactorAuth.otp.expires };
  }

  public async setup2FATOTP(
    userDTO: Setup2FAAuthenticatorDTO,
  ): Promise<{ otpAuthUrl: string }> {
    const { email, password } = userDTO;
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +passwordHash');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (!existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA not enabled for the user',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    if (existingUser.twoFactorAuth.totp.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Authenticator already enabled for the user',
      );
    }

    const secret = authenticator.generateSecret();
    const encodedSecret = await this.encrypt2FATOTPSecret(secret);
    existingUser.twoFactorAuth.totp.secret = encodedSecret;
    existingUser.twoFactorAuth.totp.enabled = true;
    await existingUser.save();

    // Generate QR code for the user
    const otpAuthUrl = authenticator.keyuri(email, meta.company.name, secret);

    // Publish events

    return { otpAuthUrl };
  }

  public async regenerate2FATOTP(
    userDTO: Setup2FAAuthenticatorDTO,
  ): Promise<{ otpAuthUrl: string }> {
    const { email, password } = userDTO;
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +passwordHash');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (!existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA not enabled for the user',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    if (!existingUser.twoFactorAuth.totp.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Authenticator not enabled for the user',
      );
    }

    const secret = authenticator.generateSecret();
    const encodedSecret = await this.encrypt2FATOTPSecret(secret);
    existingUser.twoFactorAuth.totp.secret = encodedSecret;
    await existingUser.save();

    // Generate QR code for the user
    const otpAuthUrl = authenticator.keyuri(email, meta.company.name, secret);

    // Publish events

    return { otpAuthUrl };
  }

  public async disable2FATOTP(
    userDTO: Disable2FADTO,
    _config: Disable2FAConfig,
  ): Promise<void> {
    const { email, password } = userDTO;
    const existingUser = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +passwordHash');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (!existingUser.twoFactorAuth?.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        '2FA not enabled for the user',
      );
    }

    if (!existingUser.twoFactorAuth.totp.enabled) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Authenticator not enabled for the user',
      );
    }

    const passwordsMatch = await this.comparePasswords(
      password,
      existingUser.passwordHash || '',
    );
    if (!passwordsMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect password',
      );
    }

    existingUser.twoFactorAuth.totp.secret = undefined;
    existingUser.twoFactorAuth.totp.enabled = false;
    await existingUser.save();

    // Publish events
  }

  public async loginWith2FATOTP(
    userDTO: UserOTPLoginDTO,
    config: UserLoginConfig,
  ): Promise<{
    user: IUser;
    accessToken: string;
    refreshToken: string;
  }> {
    const { token } = userDTO;
    const twoFactorAuthPayload = await this.verify2FAToken(token);

    const existingUser = await this.userModel
      .findOne({ email: twoFactorAuthPayload.email })
      .select('+twoFactorAuth +refreshTokens');
    if (!existingUser) {
      throw new AppError(
        CommonErrors.NotFound.name,
        CommonErrors.NotFound.statusCode,
        'User not found',
      );
    }

    if (
      !existingUser.twoFactorAuth?.enabled ||
      !existingUser.twoFactorAuth.totp.enabled
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Authenticator based 2FA not enabled for this user',
      );
    }

    if (
      !existingUser.twoFactorAuth.totp.secret ||
      !existingUser.twoFactorAuth.totp.enabled
    ) {
      throw new AppError(
        CommonErrors.BadRequest.name,
        CommonErrors.BadRequest.statusCode,
        'Authenticator not enabled. Please setup the authenticator first.',
      );
    }

    const secret = await this.decrypt2FATOTPSecret(
      existingUser.twoFactorAuth.totp.secret,
    );
    const otpMatch = authenticator.verify({ token, secret });
    if (!otpMatch) {
      throw new AppError(
        CommonErrors.Unauthorized.name,
        CommonErrors.Unauthorized.statusCode,
        'Incorrect OTP',
      );
    }

    // Filter expired refresh tokens
    existingUser.refreshTokens = await this.filterExpiredRefreshTokens(
      existingUser.refreshTokens || [],
    );
    // Check if device already present
    const existingRefreshToken = existingUser.refreshTokens?.find((rt) =>
      this.checkSameDevice(config.deviceInfo, rt),
    );
    if (existingRefreshToken) {
      const payload = await this.generatePayload(existingUser);
      const accessToken = await this.generateAccessToken(payload);
      const encodedRefreshToken =
        await this.encodeRefreshToken(existingRefreshToken);

      const userObject = this.excludeSensitiveFields(existingUser.toObject());
      return {
        user: userObject,
        accessToken,
        refreshToken: encodedRefreshToken,
      };
    }

    const payload = await this.generatePayload(existingUser);
    const accessToken = await this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(
      payload,
      config.deviceInfo,
    );

    existingUser.refreshTokens.push(refreshToken);
    existingUser.save();

    const userObject = this.excludeSensitiveFields(existingUser.toObject());

    // Publish events
    this.publisher.auth.publishUserLoggedInEvent({
      user: { name: userObject.name, email: userObject.email },
      deviceInfo: config.deviceInfo,
    });

    const encodedRefreshToken = await this.encodeRefreshToken(refreshToken);
    return { user: userObject, accessToken, refreshToken: encodedRefreshToken };
  }
}
