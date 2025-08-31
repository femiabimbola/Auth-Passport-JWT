import * as dotenv from "dotenv";

dotenv.config();

export const config = {
  accessTokenSecret:
    process.env.ACCESS_TOKEN_SECRET || "your-access-token-secret",
  refreshTokenSecret:
    process.env.REFRESH_TOKEN_SECRET || "your-refresh-token-secret",
  accessTokenExpiresIn: "15m",
  refreshTokenExpiresIn: "7d",
  databaseUrl: process.env.DATABASE_URL,
};
