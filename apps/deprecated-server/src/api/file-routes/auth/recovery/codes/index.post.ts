import { RequestHandler } from 'express';
import Account from '../../../../../models/account';
import { NotFoundError, UnauthorizedError } from '../../../../../utils/errors';
import {
  comparePasswords,
  decryptBackupCode,
  generateBackupCodes,
} from '../../../../../utils/auth';
import { celebrate, Joi, Segments } from 'celebrate';

const validatorMiddleware = celebrate({
  [Segments.BODY]: Joi.object().keys({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

async function regenerateRecoveryCodes(creds: {
  email: string;
  password: string;
}): Promise<{ recoveryCodes: string[] }> {
  const account = await Account.findOne({ email: creds.email }).select(
    '+passwordHash +recoveryDetails',
  );
  if (!account) throw new NotFoundError('Account not found');

  const passwordsMatch = await comparePasswords(
    creds.password,
    account.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  const recoveryCodes = await generateBackupCodes();
  account.recoveryDetails = {
    ...(account.recoveryDetails || {
      emailVerified: false,
    }),
    backupCodes: recoveryCodes.map((code) => ({ code })),
  };
  await account.save();

  const decryptedCodes = await Promise.all(
    recoveryCodes.map(decryptBackupCode),
  );

  return { recoveryCodes: decryptedCodes };
}

const regenerateRecoveryCodesHandler: RequestHandler = async (
  req,
  res,
  next,
) => {
  try {
    const creds = req.body;

    const { recoveryCodes } = await regenerateRecoveryCodes(creds);

    res.status(200).json({ recoveryCodes });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, regenerateRecoveryCodesHandler];
