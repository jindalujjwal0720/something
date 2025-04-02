import { createSlice } from '@reduxjs/toolkit';

import { RootState } from '@/stores';

export interface AuthState {
  token: string | null;
  role: string | null;
}

const initialState: AuthState = {
  token: null,
  role: null,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setAccessToken(state, action) {
      state.token = action.payload.token;
    },
    setRole: (state, action) => {
      state.role = action.payload;
    },
    clearCredentials(state) {
      state.token = null;
      state.role = null;
    },
  },
});

export const { setAccessToken, setRole, clearCredentials } = authSlice.actions;

export const selectAuthToken = (state: RootState) => state.auth.token;
export const selectRole = (state: RootState) => state.auth.role;
export const selectIsAuthenticated = (state: RootState) => !!state.auth.token;

export default authSlice.reducer;
