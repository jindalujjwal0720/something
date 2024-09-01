import { api } from '@/stores/api';
import { combineReducers } from '@reduxjs/toolkit';

import authReducer from '@/features/auth/stores/auth';

const rootReducer = combineReducers({
  [api.reducerPath]: api.reducer,

  auth: authReducer,
});

export default rootReducer;
