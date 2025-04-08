import { RequestHandler } from 'express';
import { IUser } from '../../../types/models/user';
import User from '../../../models/user';
import { IAccount } from '../../../types/models/account';
import Account from '../../../models/account';
import { NotFoundError } from '../../../utils/errors';
import { excludeSensitiveFields } from '../../../utils/auth';

async function findUserByEmail(
  accountId: string,
): Promise<{ user: IUser; account: IAccount }> {
  const account = await Account.findById(accountId).select(
    '+twoFactorAuth +recoveryDetails',
  );
  if (!account) throw new NotFoundError('Account not found');
  const sanitisedAccount = excludeSensitiveFields(account);

  const user = await User.findOne({ account: sanitisedAccount._id });
  if (!user) throw new NotFoundError('User not found');
  return { user, account: sanitisedAccount };
}

const getMeHandler: RequestHandler = async (req, res, next) => {
  try {
    const { accountId } = res.locals.user;

    const { user, account } = await findUserByEmail(accountId);

    res.status(200).json({ user, account });
  } catch (err) {
    next(err);
  }
};

export default getMeHandler;
