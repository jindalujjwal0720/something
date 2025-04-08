import { pool } from '../utils/db';
import { logger } from '../utils/logger';

const DbLoader = async () => {
  return new Promise((resolve, reject) => {
    pool.connect((err, client, done) => {
      if (err) {
        logger.error('Error connecting to the database', err);
        reject(err);
      } else {
        done(); // release the client back to the pool
        resolve(client); // resolve with the client
      }
    });
  });
};

export default DbLoader;
