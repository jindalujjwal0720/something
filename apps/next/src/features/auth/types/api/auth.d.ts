import { SanitisedAccount } from '@/types/models/account';
import { IUser } from '@/types/models/user';

export interface GetMeResponse {
  user: IUser;
  account: SanitisedAccount;
}

export interface UpdateMeDTO {
  user: Partial<IUser>;
}

export type UpdateMeResponse = void;

export interface RegisterDTO {
  user: {
    name: string;
    imageUrl?: string;
  };
  account: {
    email: string;
    password: string;
  };
}

export type RegisterResponse = void;

export interface LoginDTO {
  account: {
    email: string;
    password: string;
  };
}

export type LoginResponse =
  | { token: string; account: SanitisedAccount }
  | { requires2FA: boolean; token: string };

export type LogoutResponse = {
  message: string;
};

export interface ResetPasswordDTO {
  account: {
    email: string;
    currentPasswordOrToken: string;
    newPassword: string;
  };
}

export type ResetPasswordResponse = {
  message: string;
};

export interface RequestResetPasswordDTO {
  account: {
    email: string;
  };
}

export type RequestResetPasswordResponse = {
  message: string;
};

export interface VerifyEmailDTO {
  token: string;
}

export type VerifyEmailResponse = {
  message: string;
};

export interface ResendEmailVerificationDTO {
  account: {
    email: string;
  };
}

export type ResendEmailVerificationResponse = {
  message: string;
};

// 2FA
export interface Enable2FADTO {
  email: string;
  password: string;
}

export type Enable2FAResponse = {
  recoveryCodes: string[];
};

export interface Disable2FADTO {
  email: string;
  password: string;
}

export type Disable2FAResponse = {
  message: string;
};

export type Get2FALoginMethodsResponse = {
  methods: string[];
};

export interface Send2faOtpDTO {
  token: string;
}

export type Send2faOtpResponse = {
  message: string;
  expires: Date;
};

export interface Verify2faOtpDTO {
  token: string;
  otp: string;
}

export type Verify2faOtpResponse = {
  account: SanitisedAccount;
  token: string;
};

export interface Enable2faTotpDTO {
  email: string;
  password: string;
}

export type Enable2faTotpResponse = {
  otpAuthUrl: string;
};

export interface Disable2faTotpDTO {
  email: string;
  password: string;
}

export type Disable2faTotpResponse = {
  message: string;
};

export interface Regenerate2faTotpDTO {
  email: string;
  password: string;
}

export type Regenerate2faTotpResponse = {
  otpAuthUrl: string;
};

export interface Verify2faTotpDTO {
  token: string;
  otp: string;
}

export type Verify2faTotpResponse = {
  account: SanitisedAccount;
  token: string;
};

export interface RequestRecoveryEmailUpdateDTO {
  email: string;
  password: string;
  newRecoveryEmail: string;
}

export type RequestRecoveryEmailUpdateResponse = {
  message: string;
};

export interface RegenerateRecoveryCodesDTO {
  email: string;
  password: string;
}

export type RegenerateRecoveryCodesResponse = {
  recoveryCodes: string[];
};

export interface LoginWithRecoveryCodeDTO {
  token: string;
  code: string;
}

export type LoginWithRecoveryCodeResponse = {
  account: SanitisedAccount;
  token: string;
};
