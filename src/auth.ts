import express, { Router } from "express";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bcrypt from "bcrypt";
import { config } from "./config";
import { generateTokens, refreshAccessToken } from "./middleware";
import { findUserByEmail, findUserById } from "./db";
import { User } from "./types";
import { db } from "./db";
import * as schema from "./schema";

const router: Router = express.Router();

router.use(passport.initialize());

// Local Strategy for login
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
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
  })
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

// Register route
router.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {
    // Check if email already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    await db.insert(schema.users).values({
      email,
      password: hashedPassword,
    });

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Login route
router.post("/login", passport.authenticate("local", { session: false }), (req, res) => {
  const user = req.user as User;
  const tokens = generateTokens(user);
  res.cookie("refreshToken", tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  res.json({ accessToken: tokens.accessToken });
});

// Refresh token route
router.post("/token/refresh", refreshAccessToken, (req: any, res) => {
  if (req.newTokens) {
    res.cookie("refreshToken", req.newTokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    res.json({ accessToken: req.newTokens.accessToken });
  } else {
    res.status(403).json({ error: "Could not refresh token" });
  }
});

// Protected route
router.get("/protected", authenticateJWT, (req, res) => {
  res.json({ message: "Welcome to the protected route!", user: req.user });
});

export default router;
