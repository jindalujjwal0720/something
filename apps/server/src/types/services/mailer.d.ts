import { IUser } from '../models/user';
import { IDeviceInfo, IUserIPInfo } from '../custom/middlewares/user-agent';

export interface WelcomeEmailDTO {
  to: string;
  user: Partial<IUser>;
}

export interface EmailVerificationEmailDTO {
  to: string;
  emailVerificationToken: string;
  user: Partial<IUser>;
}

export interface LoginActivityEmailDTO {
  to: string;
  user: Partial<IUser>;
  deviceInfo: IDeviceInfo;
}

export interface ResetPasswordEmailDTO {
  to: string;
  user: Partial<IUser>;
  resetPasswordToken: string;
}

export interface PasswordChangedEmailDTO {
  to: string;
  user: Partial<IUser>;
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface ForceLoggedOutDTO {
  to: string;
  user: Partial<IUser>;
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface TwoFactorAuthOTPEmailDTO {
  to: string;
  otp: string;
  user: Partial<IUser>;
}

export interface TwoFactorAuthEnabledEmailDTO {
  to: string;
  user: Partial<IUser>;
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface TwoFactorAuthDisabledEmailDTO {
  to: string;
  user: Partial<IUser>;
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}
