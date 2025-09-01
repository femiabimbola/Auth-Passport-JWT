import jwt, { Secret, SignOptions } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { config } from "./config";
import { findUserById, findRefreshToken, insertRefreshToken, deleteRefreshToken } from "./db";
import { User } from "./types";

export const generateTokens = (user: User) => {
  const payload = { sub: user.id };
  const accessTokenOptions: SignOptions = {
    expiresIn: config.accessTokenExpiresIn as any,
  };
  const refreshTokenOptions: SignOptions = {
    expiresIn: config.refreshTokenExpiresIn as any,
  };

  const accessToken = jwt.sign(payload, config.accessTokenSecret as Secret, accessTokenOptions);
  const refreshToken = jwt.sign(payload, config.refreshTokenSecret as Secret, refreshTokenOptions);

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  insertRefreshToken(user.id, refreshToken, expiresAt);
  return { accessToken, refreshToken };
};

export const refreshAccessToken = async (req: any, res: Response, next: NextFunction) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(403).json({ error: "Missing refresh token" });
  }

  const storedToken = await findRefreshToken(refreshToken);
  if (!storedToken || storedToken.expiresAt < new Date()) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.refreshTokenSecret as Secret) as unknown as { sub: number };

    if (!decoded.sub || typeof decoded.sub !== "number") {
      return res.status(403).json({ error: "Invalid token payload" });
    }

    const user = await findUserById(decoded.sub);

    if (!user) {
      return res.status(403).json({ error: "User not found" });
    }

    const payload = { sub: user.id };
    const accessTokenOptions: SignOptions = {
      expiresIn: config.accessTokenExpiresIn as any,
    };
    const newAccessToken = jwt.sign(payload, config.accessTokenSecret as Secret, accessTokenOptions);
    await deleteRefreshToken(refreshToken);
    const refreshTokenOptions: SignOptions = {
      expiresIn: config.refreshTokenExpiresIn as any,
    };
    const newRefreshToken = jwt.sign(payload, config.refreshTokenSecret as Secret, refreshTokenOptions);
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
