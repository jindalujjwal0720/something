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
    // Recovery details sensitive fields
    if (user.recoveryDetails) {
      user.recoveryDetails.backupCodesUsedCount =
        user.recoveryDetails.backupCodes.filter((code) => code.usedAt).length;
      user.recoveryDetails.backupCodes = [];
    }
    return user;
  }

  public async findUserByEmail(email: string): Promise<IUser | null> {
    const user = await this.userModel
      .findOne({ email })
      .select('+twoFactorAuth +recoveryDetails');
    return user ? this.excludeSensitiveFields(user.toObject()) : null;
  }

  public async updateUserByEmail(
    email: string,
    updates: Partial<IUser>,
  ): Promise<IUser | null> {
    // only allow updating non sensitive fields
    const update = {
      name: updates.name,
      imageUrl: updates.imageUrl,
    };
    const user = await this.userModel
      .findOneAndUpdate({ email }, update, {
        new: true,
      })
      .select('+twoFactorAuth +recoveryDetails');
    return user ? this.excludeSensitiveFields(user.toObject()) : null;
  }
}
