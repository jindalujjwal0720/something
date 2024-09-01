import express from 'express';
import { AuthController } from '../controllers/auth';
import { AuthValidators } from '../validators/auth';
import { UserAgentMiddleware } from '../middlewares/user-agent';
import { RateLimiterMiddleware } from '../middlewares/rate-limit';

const router = express.Router();
const authController = new AuthController();
const authValidators = new AuthValidators();
const userAgentMiddleware = new UserAgentMiddleware();
const rateLimiterMiddleware = new RateLimiterMiddleware();

router.post(
  '/register',
  rateLimiterMiddleware.emailLimiter,
  authValidators.validateRegisterData.bind(authValidators),
  authController.register.bind(authController),
);
router.get(
  '/verify-email',
  rateLimiterMiddleware.limiter,
  authValidators.validateVerifyEmailData.bind(authValidators),
  authController.verifyEmail.bind(authController),
);
router.post(
  '/resend-verification-email',
  rateLimiterMiddleware.emailLimiter,
  authValidators.validateResendEmailVerificationData.bind(authValidators),
  authController.resendEmailVerification.bind(authController),
);
router.post(
  '/login',
  rateLimiterMiddleware.limiter,
  authValidators.validateLoginWithEmailPasswordData.bind(authValidators),
  authController.loginWithEmailAndPassword.bind(authController),
);
router.post(
  '/logout',
  rateLimiterMiddleware.limiter,
  authController.logout.bind(authController),
);
router.get(
  '/refresh',
  rateLimiterMiddleware.limiter,
  userAgentMiddleware.extractIpInfo.bind(userAgentMiddleware),
  authController.refreshTokens.bind(authController),
);
router.post(
  '/reset-password',
  rateLimiterMiddleware.emailLimiter,
  userAgentMiddleware.extractIpInfo.bind(userAgentMiddleware),
  authValidators.validateResetPasswordData.bind(authValidators),
  authController.resetPassword.bind(authController),
);
router.post(
  '/request-password-reset',
  rateLimiterMiddleware.emailLimiter,
  authValidators.validateRequestPasswordResetData.bind(authValidators),
  authController.requestPasswordReset.bind(authController),
);

// 2FA
router.post(
  '/2fa/enable',
  rateLimiterMiddleware.limiter,
  userAgentMiddleware.extractDeviceInfo.bind(userAgentMiddleware),
  authValidators.validate2FAEnableData.bind(authValidators),
  authController.enable2FA.bind(authController),
);
router.post(
  '/2fa/disable',
  rateLimiterMiddleware.limiter,
  userAgentMiddleware.extractDeviceInfo.bind(userAgentMiddleware),
  authValidators.validate2FADisableData.bind(authValidators),
  authController.disable2FA.bind(authController),
);
router.get(
  '/2fa/methods',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FALoginMethodsData.bind(authValidators),
  authController.get2FALoginMethods.bind(authController),
);
router.post(
  '/2fa/otp',
  rateLimiterMiddleware.emailLimiter,
  authValidators.validate2FAOTPSendData.bind(authValidators),
  authController.send2FAOTP.bind(authController),
);
router.post(
  '/2fa/otp/verify',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FAOTPLoginData.bind(authValidators),
  authController.loginWith2FAOTP.bind(authController),
);
router.post(
  '/2fa/totp/enable',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FAAuthenticatorSetupData.bind(authValidators),
  authController.setup2FATOTP.bind(authController),
);
router.post(
  '/2fa/totp/regenerate',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FARegenerateData.bind(authValidators),
  authController.regenerate2FATOTP.bind(authController),
);
router.post(
  '/2fa/totp/disable',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FADisableData.bind(authValidators),
  authController.disable2FATOTP.bind(authController),
);
router.post(
  '/2fa/totp/verify',
  rateLimiterMiddleware.limiter,
  authValidators.validate2FATOTPLoginData.bind(authValidators),
  authController.loginWith2FATOTP.bind(authController),
);

export default router;
