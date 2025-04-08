import * as express from 'express';
import expressLoader from './express';
import DbLoader from './db';
import { logger } from '../utils/logger';
import subscribersLoader from './subscribers';
import { errorLoader } from './error';

interface InitLoadersProps {
  expressApp: express.Application;
}

const initLoaders = async ({ expressApp }: InitLoadersProps) => {
  // Load express loader
  await expressLoader({ app: expressApp });
  logger.info('Express loaded');
  // Load error loader
  await errorLoader({ app: expressApp });
  logger.info('Error loaded');
  // Load mongoose loader
  await DbLoader();
  logger.info('Database loaded');
  // Load subscribers
  await subscribersLoader();
  logger.info('Subscribers loaded');
};

export default initLoaders;
