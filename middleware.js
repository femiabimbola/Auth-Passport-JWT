const jwt = require("jsonwebtoken");
const config = require("./config");
const bcrypt = require("bcrypt");

// Mock database for refresh tokens (replace with actual database, e.g., MongoDB)
const refreshTokens = {};

// Middleware to generate tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign({ sub: user.id }, config.accessTokenSecret, {
    expiresIn: config.accessTokenExpiresIn,
  });
  const refreshToken = jwt.sign({ sub: user.id }, config.refreshTokenSecret, {
    expiresIn: config.refreshTokenExpiresIn,
  });
  // Store refresh token (replace with database)
  refreshTokens[refreshToken] = user.id;
  return { accessToken, refreshToken };
};

// Middleware to validate refresh token and issue new access token
const refreshAccessToken = (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken || !refreshTokens[refreshToken]) {
    return res.status(403).json({ error: "Invalid or missing refresh token" });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.refreshTokenSecret);
    const user = users.find((u) => u.id === decoded.sub);
    if (!user) {
      return res.status(403).json({ error: "User not found" });
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { sub: user.id },
      config.accessTokenSecret,
      {
        expiresIn: config.accessTokenExpiresIn,
      }
    );

    // Rotate refresh token
    delete refreshTokens[refreshToken];
    const newRefreshToken = jwt.sign(
      { sub: user.id },
      config.refreshTokenSecret,
      {
        expiresIn: config.refreshTokenExpiresIn,
      }
    );
    refreshTokens[newRefreshToken] = user.id;

    req.newTokens = {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }
};

// Export mock users for auth.js (replace with database)
const users = [
  {
    id: 1,
    email: "user@example.com",
    password: bcrypt.hashSync("password", 10), // Hashed password
  },
];

module.exports = { generateTokens, refreshAccessToken, users };
