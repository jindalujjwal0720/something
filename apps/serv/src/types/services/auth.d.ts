export interface TokenPayload {
  accountId: string;
  email: string;
  roles: string[];
  mfaVerified: boolean; // true is current session has 2FA verified
}

export interface AccountChooser {
  current: string; // the current account refresh token cookie name
  accounts: string[]; // list of cookie names which contain the account refresh token
}
