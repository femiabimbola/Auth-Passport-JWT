import express, { Express } from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import authRoutes from "./auth";

const app: Express = express();

app.use(bodyParser.json());
app.use(cookieParser());

// Routes
app.use("/auth", authRoutes);

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
