export type ITwoFactorAuth = {
  enabled: boolean; // 2FA enabled or not
  otp: {
    enabled: boolean; // OTP enabled or not
  };
  // for authenticator apps
  totp: {
    enabled: boolean; // TOTP enabled or not
  };
};

export type IRecoveryDetails = {
  backupCodes: string[];
  email?: string;
  emailVerified?: boolean;
  backupCodesUsedCount?: number;
};

export interface IUser {
  _id: string;
  // Base properties, required for creating a new user
  // Optional because we will check for these in application code
  name: string;
  email: string;
  imageUrl?: string;
  // Authorization
  roles: IUserRole[];
  restricted?: string[]; // List of restricted permissions
  // Authentication
  isEmailVerified?: boolean;
  // 2FA
  twoFactorAuth?: ITwoFactorAuth;
  recoveryDetails?: IRecoveryDetails;

  createdAt: Date;
  updatedAt: Date;
}
