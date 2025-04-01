import { RequestHandler } from 'express';
import { RegenerateRecoveryCodesDTO } from '../../../../../types/services/auth';
import User from '../../../../../models/user';
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

async function regenerateRecoveryCodes(
  userDTO: RegenerateRecoveryCodesDTO,
): Promise<{ recoveryCodes: string[] }> {
  const existingUser = await User.findOne({ email: userDTO.email }).select(
    '+passwordHash +recoveryDetails',
  );
  if (!existingUser) {
    throw new NotFoundError('User not found');
  }

  const passwordsMatch = await comparePasswords(
    userDTO.password,
    existingUser.passwordHash || '',
  );
  if (!passwordsMatch) {
    throw new UnauthorizedError('Incorrect password');
  }

  const recoveryCodes = await generateBackupCodes();
  existingUser.recoveryDetails = {
    ...(existingUser.recoveryDetails || {
      emailVerified: false,
    }),
    backupCodes: recoveryCodes.map((code) => ({ code })),
  };
  await existingUser.save();

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
    const user = req.body;

    const { recoveryCodes } = await regenerateRecoveryCodes(user);

    res.status(200).json({ recoveryCodes });
  } catch (err) {
    next(err);
  }
};

export default [validatorMiddleware, regenerateRecoveryCodesHandler];
