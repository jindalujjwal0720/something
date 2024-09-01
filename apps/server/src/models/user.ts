import mongoose from 'mongoose';
import { IUser, IRefreshToken } from '../types/models/user.d';

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

const updatesSchema = new mongoose.Schema<
  Pick<IUser, 'name' | 'email' | 'imageUrl'>
>(
  {
    name: { type: String, minlength: 3, maxlength: 50 },
    email: {
      type: String,
      validate: {
        validator: (v: string) => {
          // eslint-disable-next-line no-useless-escape
          return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v);
        },
        message: (props) => `${props.value} is not a valid email address!`,
      },
    },
    imageUrl: { type: String },
  },
  { _id: false },
);

const twoFactorAuthSchema = new mongoose.Schema(
  {
    enabled: { type: Boolean, default: false },
    otp: {
      enabled: { type: Boolean, default: false },
      hash: { type: String },
      expires: { type: Date },
    },
    totp: {
      enabled: { type: Boolean, default: false },
      encryptedSecret: { type: String },
    },
  },
  { _id: false },
);

const userSchema = new mongoose.Schema<IUser>(
  {
    name: { type: String, required: true, minlength: 3, maxlength: 50 },
    email: {
      type: String,
      required: true,
      unique: true,
      validate: {
        validator: (v: string) => {
          // eslint-disable-next-line no-useless-escape
          return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v);
        },
        message: (props) => `${props.value} is not a valid email address!`,
      },
    },
    imageUrl: { type: String },
    passwordHash: { type: String, required: true, select: false },

    updates: { type: updatesSchema, select: false },
    reason: { type: String, maxlength: 255, select: false },

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
  },
  { timestamps: true },
);

const User = mongoose.model('User', userSchema);
export default User;
