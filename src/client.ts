// To stimulate cilent calls

import axios, { AxiosError, AxiosRequestConfig } from "axios";

// Base URL for your Express server
const API_URL = "http://localhost:3000";

// Store access token in memory (or localStorage, depending on your needs)
let accessToken: string | null = null;

// Function to set access token (e.g., after login or refresh)
export function setAccessToken(token: string) {
  accessToken = token;
}

// Function to get access token
export function getAccessToken(): string | null {
  return accessToken;
}

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Interceptor to add Authorization header with access token
api.interceptors.request.use(
  (config: any) => {
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: any) => Promise.reject(error)
);

// Interceptor to handle 401 errors and refresh token
api.interceptors.response.use(
  (response: any) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true; // Prevent infinite retry loops
      try {
        // Call /auth/token/refresh (browser sends refreshToken cookie automatically)
        const response = await axios.post(`${API_URL}/auth/token/refresh`, {});
        const { accessToken: newAccessToken } = response.data;

        // Update stored access token
        setAccessToken(newAccessToken);

        // Retry the original request with the new access token
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        console.error("Token refresh failed:", refreshError);
        // Redirect to login page if refresh token is invalid or expired
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

// Function to access a protected route
export async function accessProtectedRoute(): Promise<{ message: string; user: { id: number; email: string } }> {
  try {
    const response = await api.get("/protected");
    return response.data;
  } catch (error) {
    console.error("Failed to access protected route:", error);
    throw error;
  }
}

// Example usage
async function main() {
  // Simulate login (normally done via POST /auth/login)
  try {
    const loginResponse = await axios.post(`${API_URL}/auth/login`, {
      email: "user@example.com",
      password: "password123",
    });
    setAccessToken(loginResponse.data.accessToken);
    console.log("Logged in successfully");

    // Access protected route
    const protectedData = await accessProtectedRoute();
    console.log("Protected route data:", protectedData);
  } catch (error) {
    console.error("Error:", error);
  }
}

// Run example
main();
