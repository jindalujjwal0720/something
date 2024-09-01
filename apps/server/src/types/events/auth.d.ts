import { IDeviceInfo, IUserIPInfo } from '../middlewares/user-agent';

export interface UserRegisteredEventData {
  user: {
    name: string;
    email: string;
  };
}

export interface UserEmailVerificationRequestedEventData {
  user: {
    name: string;
    email: string;
  };
  emailVerificationToken: string;
}

export interface UserLoggedInEventData {
  user: {
    name: string;
    email: string;
  };
  deviceInfo: IDeviceInfo;
}

export interface UserForceLoggedOutEventData {
  user: {
    name: string;
    email: string;
  };
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface UserPasswordChangeRequestedEventData {
  user: {
    name: string;
    email: string;
  };
  resetPasswordToken: string;
}

export interface UserPasswordChangedEventData {
  user: {
    name: string;
    email: string;
  };
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface User2FAEnabledEventData {
  user: {
    name: string;
    email: string;
  };
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface User2FADisabledEventData {
  user: {
    name: string;
    email: string;
  };
  deviceInfo: IDeviceInfo;
  ipInfo: IUserIPInfo;
}

export interface User2faOtpGeneratedEventData {
  user: {
    name: string;
    email: string;
  };
  otp: string;
}
