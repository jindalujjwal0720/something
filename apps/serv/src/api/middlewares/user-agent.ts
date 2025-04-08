import { RequestHandler } from 'express';
import { fetchIPaddressInfo } from '../../utils/user-agent';
import { errorLogger } from '../../utils/logger';

export const extractDeviceInfo: RequestHandler = (req, res, next) => {
  try {
    const di = {
      browser: req.useragent?.browser || 'unknown',
      os: req.useragent?.os || 'unknown',
      platform: req.useragent?.platform || 'unknown',
      source: req.useragent?.source || 'unknown',
    };

    res.locals.deviceInfo = di;
    next();
  } catch (err) {
    next(err);
  }
};

export const extractIpInfo: RequestHandler = async (req, res, next) => {
  try {
    const ipInfo = await fetchIPaddressInfo(req.ip || 'unknown');
    res.locals.ipInfo = ipInfo;
    next();
  } catch (_err) {
    errorLogger.error('IP fetch error');
    // ignore error
    next();
  }
};
