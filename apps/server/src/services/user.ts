import { Model } from 'mongoose';
import { IUser } from '../types/models/user';

export class UserService {
  private userModel: Model<IUser>;

  constructor(userModel: Model<IUser>) {
    this.userModel = userModel;
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

  public async findUserByEmail(email: string): Promise<IUser | null> {
    const user = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth');
    return user ? this.excludeSensitiveFields(user) : null;
  }
}
