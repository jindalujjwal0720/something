import { IDeviceInfo, IUserIPInfo } from '../custom/middlewares/user-agent';
import { IUser } from '../models/user';

export interface UserRegisterDTO {
  name: string;
  email: string;
  password: string;
  imageUrl?: string;
}

export interface UserOTPLoginDTO {
  token: string;
  otp: string;
}

export interface UserLoginDTO {
  email: string;
  password: string;
}

export type UserLoginResponse =
  | {
      user: IUser;
      accessToken: string;
      refreshToken: string;
    }
  | {
      requires2FA: boolean;
      token: string; // token to be used for getting user's details
    };

export interface UserLoginConfig {
  deviceInfo: IDeviceInfo;
}

export interface TokenPayload {
  email: string;
  name: string;
  imageUrl?: string;
  roles: string[];
  mfaVerified: boolean; // true is current session has 2FA verified
}

export interface UserRefreshTokensConfig {
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface RequestPasswordResetDTO {
  email: string;
  logoutAllDevices?: boolean;
}

export interface ResetPasswordDTO {
  user: {
    email: string;
    currentPasswordOrToken: string;
    newPassword: string;
  };
  logoutAllDevices?: boolean;
}

export interface ResetPasswordConfig {
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface AccountChooser {
  current: string; // the current account refresh token cookie name
  accounts: string[]; // list of cookie names which contain the account refresh token
}

export interface Enable2FADTO {
  email: string;
  password: string;
}

export interface Enable2FAConfig {
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface Disable2FADTO {
  email: string;
  password: string;
}

export interface Disable2FAConfig {
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface Setup2FAAuthenticatorDTO {
  email: string;
  password: string;
}

export interface UpdateRecoveryEmailDTO {
  email: string;
  password: string;
  newRecoveryEmail: string;
}

export interface RegenerateRecoveryCodesDTO {
  email: string;
  password: string;
}

export interface UserRecoveryCodeLoginDTO {
  token: string;
  code: string;
}
