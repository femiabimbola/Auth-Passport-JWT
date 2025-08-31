import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { config } from "./config";
import {
  findUserById,
  findRefreshToken,
  insertRefreshToken,
  deleteRefreshToken,
} from "./db";
import { User } from "./types";

export const generateTokens = (user: User) => {
  const accessToken = jwt.sign({ sub: user.id }, config.accessTokenSecret, {
    expiresIn: config.accessTokenExpiresIn,
  });
  const refreshToken = jwt.sign({ sub: user.id }, config.refreshTokenSecret, {
    expiresIn: config.refreshTokenExpiresIn,
  });
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  insertRefreshToken(user.id, refreshToken, expiresAt);
  return { accessToken, refreshToken };
};

export const refreshAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(403).json({ error: "Missing refresh token" });
  }

  const storedToken = await findRefreshToken(refreshToken);
  if (!storedToken || storedToken.expiresAt < new Date()) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.refreshTokenSecret) as {
      sub: number;
    };
    const user = await findUserById(decoded.sub);
    if (!user) {
      return res.status(403).json({ error: "User not found" });
    }

    const newAccessToken = jwt.sign(
      { sub: user.id },
      config.accessTokenSecret,
      {
        expiresIn: config.accessTokenExpiresIn,
      }
    );
    await deleteRefreshToken(refreshToken);
    const newRefreshToken = jwt.sign(
      { sub: user.id },
      config.refreshTokenSecret,
      {
        expiresIn: config.refreshTokenExpiresIn,
      }
    );
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await insertRefreshToken(user.id, newRefreshToken, expiresAt);

    req.newTokens = {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }
};
