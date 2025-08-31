import type { Config } from "drizzle-kit";
import { config } from "./src/config";

// Validate databaseUrl to prevent undefined connectionString
if (!config.databaseUrl) {
  throw new Error("DATABASE_URL is not defined in the environment variables");
}

export default {
  schema: "./src/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: config.databaseUrl,
  },
} satisfies Config;
