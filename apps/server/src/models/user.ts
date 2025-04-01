import mongoose from 'mongoose';
import { IUser } from '../types/models/user';

const userSchema = new mongoose.Schema<IUser>(
  {
    account: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Account',
      required: true,
    },
    name: { type: String, required: true, minlength: 3, maxlength: 50 },
    imageUrl: { type: String },
  },
  {
    timestamps: true,
  },
);

const User = mongoose.model<IUser>('User', userSchema);
export default User;
