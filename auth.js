const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");
const bcrypt = require("bcrypt");
const config = require("./config");
const { generateTokens, refreshAccessToken, users } = require("./middleware");

const router = express.Router();

// Initialize Passport for this router
router.use(passport.initialize());

// Local Strategy for login
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      const user = users.find((u) => u.email === email);
      if (!user) {
        return done(null, false, { message: "Incorrect email." });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect password." });
      }
      return done(null, user);
    }
  )
);

// JWT Strategy for verifying access tokens
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.accessTokenSecret,
};

passport.use(
  new JwtStrategy(jwtOptions, (jwtPayload, done) => {
    const user = users.find((u) => u.id === jwtPayload.sub);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  })
);

// Middleware to verify access token
const authenticateJWT = passport.authenticate("jwt", { session: false });

// Login route
router.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const tokens = generateTokens(req.user);
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
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

module.exports = router;
