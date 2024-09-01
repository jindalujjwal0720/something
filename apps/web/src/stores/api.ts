import {
  BaseQueryApi,
  createApi,
  FetchArgs,
  fetchBaseQuery,
} from '@reduxjs/toolkit/query/react';
import {
  clearCredentials,
  setAccessToken,
  setRole,
} from '@/features/auth/stores/auth';
import { RootState } from '@/stores';

const baseQuery = fetchBaseQuery({
  baseUrl: import.meta.env.VITE_API_URL as string,
  credentials: 'include',
  prepareHeaders: (headers, { getState }) => {
    const token = (getState() as RootState).auth.token;
    if (token) {
      headers.set('authorization', `Bearer ${token}`);
    }
    return headers;
  },
});

const baseQueryWithRefresh = async (
  args: string | FetchArgs,
  api: BaseQueryApi,
  extraOptions = {},
) => {
  let result = await baseQuery(args, api, extraOptions);
  if (result.error?.status === 401) {
    const refreshResult = await baseQuery(
      '/v1/auth/refresh',
      api,
      extraOptions,
    );
    if (refreshResult?.data) {
      api.dispatch(setAccessToken(refreshResult.data));
      api.dispatch(
        setRole(
          (refreshResult.data as { user: { roles: string[] } }).user
            ?.roles?.[0],
        ),
      );
      result = await baseQuery(args, api, extraOptions);
    } else {
      api.dispatch(clearCredentials());
    }
  }
  return result;
};

export const api = createApi({
  baseQuery: baseQueryWithRefresh,
  endpoints: () => ({}),
  tagTypes: [
    'Auth', // This is a tag for the auth related endpoints
  ],
});
