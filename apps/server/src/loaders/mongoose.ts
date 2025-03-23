import * as mongoose from 'mongoose';
import { env } from '../config';

const mongooseLoader = async () => {
  let connection;
  if (env.db.endpoint) {
    connection = await mongoose.connect(env.db.endpoint);
  } else {
    connection = await mongoose.connect(
      `mongodb://${env.db.host}:${env.db.port}/${env.db.name}`,
    );
  }

  return connection.connection.db;
};

export default mongooseLoader;
