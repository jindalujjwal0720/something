export interface APIErrorResponse {
  error: {
    name: string;
    status: number;
    message: string;
  };
}
