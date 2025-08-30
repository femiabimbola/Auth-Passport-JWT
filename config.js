module.exports = {
  accessTokenSecret:
    process.env.ACCESS_TOKEN_SECRET || "your-access-token-secret",
  refreshTokenSecret:
    process.env.REFRESH_TOKEN_SECRET || "your-refresh-token-secret",
  accessTokenExpiresIn: "15m", // Access token expires in 15 minutes
  refreshTokenExpiresIn: "7d", // Refresh token expires in 7 days
};
