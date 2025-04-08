import mongoose from 'mongoose';
import {
  IAccount,
  IRefreshToken,
  ITwoFactorAuth,
  IRecoveryDetails,
} from '../types/models/account';

const refreshTokenSchema = new mongoose.Schema<IRefreshToken>(
  {
    token: { type: String, required: true },
    expires: { type: Date, required: true },
    deviceInfo: {
      browser: String,
      os: String,
      platform: String,
      source: String,
    },
  },
  { _id: false },
);

const twoFactorAuthSchema = new mongoose.Schema<ITwoFactorAuth>(
  {
    enabled: { type: Boolean, default: false },
    otp: {
      enabled: { type: Boolean, default: false },
      hash: { type: String },
      expires: { type: Date },
    },
    totp: {
      enabled: { type: Boolean, default: false },
      secret: { type: String },
    },
  },
  { _id: false },
);

const recoveryDetailsSchema = new mongoose.Schema<IRecoveryDetails>(
  {
    backupCodes: [
      {
        code: { type: String, required: true },
        usedAt: { type: Date },
      },
    ],
    email: { type: String },
    emailVerified: { type: Boolean },
  },
  {
    _id: false,
  },
);

const accountSchema = new mongoose.Schema<IAccount>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      validate: {
        validator: (v: string) => {
          return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v);
        },
        message: (props) => `${props.value} is not a valid email address!`,
      },
    },
    passwordHash: { type: String, required: true, select: false },

    roles: {
      type: [String],
      validate: {
        validator: (v: string[]) => {
          return ['user', 'admin'].some((role) => v.includes(role));
        },
        message: (props) => `${props.value} is not a valid role!`,
      },
      default: ['user'],
    },
    restricted: [{ type: String }],

    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpires: { type: Date, select: false },
    isEmailVerified: { type: Boolean, default: false },
    resetPasswordToken: { type: String, select: false },
    resetPasswordTokenExpires: { type: Date, select: false },

    refreshTokens: {
      type: [refreshTokenSchema],
      default: [],
      index: true,
      select: false,
    },

    twoFactorAuth: {
      type: twoFactorAuthSchema,
      default: {
        enabled: false,
        otp: { enabled: true }, // OTP enabled by default
        totp: { enabled: false },
      },
      select: false,
    },

    recoveryDetails: {
      type: recoveryDetailsSchema,
      default: {
        backupCodes: [],
        emailVerified: false,
      },
      select: false,
    },
  },
  { timestamps: true },
);

const Account = mongoose.model('Account', accountSchema);
export default Account;
