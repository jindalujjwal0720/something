import { IDeviceInfo, IUserIPInfo } from '../../types/middlewares/user-agent';

export enum AuthenticationEvent {
  REGISTERED = 'registered',
  LOGGED_IN = 'logged-in',
  EMAIL_VERIFICATION_REQUESTED = 'email-verification-requested',
  FORCE_LOGGED_OUT = 'force-logged-out',
  PASSWORD_CHANGE_REQUESTED = 'password-change-requested',
  PASSWORD_CHANGED = 'password-changed',
  TWO_FACTOR_AUTH_ENABLED = '2fa-enabled',
  TWO_FACTOR_AUTH_DISABLED = '2fa-disabled',
  TWO_FACTOR_AUTH_OTP_GENERATED = '2fa-otp-generated',
  TWO_FACTOR_AUTH_RECOVERY_OTP_GENERATED = '2fa-recovery-otp-generated',
  RECOVERY_EMAIL_UPDATE_REQUESTED = 'recovery-email-update-requested',
}

export type AuthenticationEventTypes = {
  [AuthenticationEvent.REGISTERED]: {
    user: { name: string; email: string };
  };
  [AuthenticationEvent.LOGGED_IN]: {
    user: { name: string; email: string };
    deviceInfo: IDeviceInfo;
  };
  [AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED]: {
    user: { name: string; email: string };
    emailVerificationToken: string;
    tokenExpiresInSeconds: number;
  };
  [AuthenticationEvent.FORCE_LOGGED_OUT]: {
    user: { name: string; email: string };
    deviceInfo: IDeviceInfo;
    ipInfo: IUserIPInfo;
  };
  [AuthenticationEvent.PASSWORD_CHANGE_REQUESTED]: {
    user: { name: string; email: string };
    resetPasswordToken: string;
    tokenExpiresInSeconds: number;
  };
  [AuthenticationEvent.PASSWORD_CHANGED]: {
    user: { name: string; email: string };
    deviceInfo: IDeviceInfo;
    ipInfo: IUserIPInfo;
  };
  [AuthenticationEvent.TWO_FACTOR_AUTH_ENABLED]: {
    user: { name: string; email: string };
    deviceInfo: IDeviceInfo;
    ipInfo: IUserIPInfo;
  };
  [AuthenticationEvent.TWO_FACTOR_AUTH_DISABLED]: {
    user: { name: string; email: string };
    deviceInfo: IDeviceInfo;
    ipInfo: IUserIPInfo;
  };
  [AuthenticationEvent.TWO_FACTOR_AUTH_OTP_GENERATED]: {
    user: { name: string; email: string };
    otp: string;
    optExpiresInSeconds: number;
  };
  [AuthenticationEvent.TWO_FACTOR_AUTH_RECOVERY_OTP_GENERATED]: {
    user: { name: string; email: string };
    recoveryEmail: string;
    otp: string;
    optExpiresInSeconds: number;
  };
  [AuthenticationEvent.RECOVERY_EMAIL_UPDATE_REQUESTED]: {
    user: { name: string; email: string };
    recoveryEmail: string;
    emailVerificationToken: string;
    tokenExpiresInSeconds: number;
  };
};
