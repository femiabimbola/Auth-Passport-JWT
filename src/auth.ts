import express, { Router } from "express";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bcrypt from "bcrypt";
import { config } from "./config";
import { generateTokens, refreshAccessToken } from "./middleware";
import { findUserByEmail, findUserById } from "./db";
import { User } from "./types";

const router: Router = express.Router();

router.use(passport.initialize());

// Local Strategy for login
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await findUserByEmail(email);
        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// JWT Strategy for verifying access tokens
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.accessTokenSecret,
};

passport.use(
  new JwtStrategy(jwtOptions, async (jwtPayload: { sub: number }, done) => {
    try {
      const user = await findUserById(jwtPayload.sub);
      if (user) {
        return done(null, user);
      }
      return done(null, false);
    } catch (error) {
      return done(error, false);
    }
  })
);

const authenticateJWT = passport.authenticate("jwt", { session: false });

// Login route
router.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const tokens = generateTokens(req.user as User);
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    res.json({ accessToken: tokens.accessToken });
  }
);

// Refresh token route
router.post("/token/refresh", refreshAccessToken, (req, res) => {
  res.json(req.newTokens);
});

// Protected route
router.get("/protected", authenticateJWT, (req, res) => {
  res.json({ message: "Welcome to the protected route!", user: req.user });
});

export default router;
