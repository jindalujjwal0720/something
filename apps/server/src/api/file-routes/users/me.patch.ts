import { RequestHandler } from 'express';
import { IUser } from '../../../types/models/user';
import User from '../../../models/user';

const updateUserByEmail = async (
  accountId: string,
  updates: Partial<IUser>,
): Promise<void> => {
  await User.findOneAndUpdate(
    { account: accountId },
    { $set: updates },
    { new: true, runValidators: true },
  );
};

const updateMeHandler: RequestHandler = async (req, res, next) => {
  try {
    const { accountId } = res.locals.user;
    const updates = req.body || {};

    await updateUserByEmail(accountId, updates);

    res.status(200).send();
  } catch (err) {
    next(err);
  }
};

export default updateMeHandler;
