import * as express from 'express';
import expressLoader from './express';
import mongooseLoader from './mongoose';
import { logger } from '../utils/logger';
import subscribersLoader from './subscribers';
import { frontendLoader } from './frontend';
import { errorLoader } from './error';

interface InitLoadersProps {
  expressApp: express.Application;
}

const initLoaders = async ({ expressApp }: InitLoadersProps) => {
  // Load express loader
  await expressLoader({ app: expressApp });
  logger.info('Express loaded');
  // Load frontend loader
  await frontendLoader({ app: expressApp });
  logger.info('Frontend loaded');
  // Load error loader
  await errorLoader({ app: expressApp });
  logger.info('Error loaded');
  // Load mongoose loader
  await mongooseLoader();
  logger.info('MongoDB loaded');
  // Load subscribers
  await subscribersLoader();
  logger.info('Subscribers loaded');
};

export default initLoaders;
