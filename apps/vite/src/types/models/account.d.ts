import { IDeviceInfo } from '../custom/middlewares/user-agent';

export type IAccountRole = 'user' | 'admin';

export type IRefreshToken = {
  token: string;
  expires: Date;
  deviceInfo?: IDeviceInfo;
};

export type ITwoFactorAuth = {
  enabled: boolean; // 2FA enabled or not
  otp: {
    enabled: boolean; // OTP enabled or not
    hash?: string; // Hashed OTP
    expires?: Date;
  };
  // for authenticator apps
  totp: {
    enabled: boolean; // TOTP enabled or not
    secret?: string;
  };
};

export type IBackupCode = {
  code: string;
  usedAt?: Date;
};

export type IRecoveryDetails = {
  backupCodes: IBackupCode[];
  email?: string;
  emailVerified?: boolean;
  backupCodesUsedCount?: number;
};

export interface IAccount {
  _id: string;

  // Authorization
  roles: IAccountRole[];
  restricted?: string[]; // List of restricted permissions

  // Authentication
  email: string;
  passwordHash?: string;
  emailVerificationToken?: string;
  emailVerificationTokenExpires?: Date;
  isEmailVerified?: boolean;
  resetPasswordToken?: string;
  resetPasswordTokenExpires?: Date;
  refreshTokens?: IRefreshToken[];

  // 2FA
  twoFactorAuth?: ITwoFactorAuth;
  // Recovery
  recoveryDetails?: IRecoveryDetails;
}

export type SanitisedAccount = Omit<
  IAccount,
  | 'passwordHash'
  | 'emailVerificationToken'
  | 'emailVerificationTokenExpires'
  | 'resetPasswordToken'
  | 'resetPasswordTokenExpires'
  | 'refreshTokens'
  | 'twoFactorAuth'
> & {
  twoFactorAuth: {
    enabled: boolean;
    otp: {
      enabled: boolean;
    };
    totp: {
      enabled: boolean;
    };
  };
};
