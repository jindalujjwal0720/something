import { IAccount } from './account';

export interface IUser {
  _id: string;

  account: string;
  name: string;
  imageUrl?: string;

  createdAt: Date;
  updatedAt: Date;
}
