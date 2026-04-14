/* eslint-disable no-console */
const BASE_URL = process.env.SECURITY_TEST_BASE_URL || "http://127.0.0.1:5001";

const checks = [
  {
    name: "Register duplicate user should not enumerate",
    method: "POST",
    path: "/api/auth/register",
    body: {username: "knownuser", email: "known@example.com", password: "Passw0rd!Passw0rd!"},
    forbiddenTokens: ["already exists", "duplicate", "E11000"],
  },
  {
    name: "Auth failure should not expose stack/database",
    method: "POST",
    path: "/api/auth/login",
    body: {username: "nouser", password: "bad-pass"},
    forbiddenTokens: ["stack", "Mongo", "CastError", "ValidationError", "node_modules"],
  },
  {
    name: "Not found should be generic",
    method: "GET",
    path: "/api/posts/not-a-real-slug",
    forbiddenTokens: ["Exception", "trace", "Error:"],
  },
];

async function run() {
  let failures = 0;

  for (const check of checks) {
    try {
      const response = await fetch(`${BASE_URL}${check.path}`, {
        method: check.method,
        headers: {"Content-Type": "application/json"},
        body: check.body ? JSON.stringify(check.body) : undefined,
      });

      const text = await response.text();
      const leaked = check.forbiddenTokens.filter((token) =>
        text.toLowerCase().includes(token.toLowerCase()),
      );

      if (leaked.length > 0) {
        failures += 1;
        console.error(`FAIL: ${check.name}`);
        console.error(`Leaked tokens: ${leaked.join(", ")}`);
      } else {
        console.log(`PASS: ${check.name}`);
      }
    } catch (error) {
      failures += 1;
      console.error(`ERROR: ${check.name} -> ${error.message}`);
    }
  }

  if (failures > 0) {
    console.error(`\nSecurity leakage checks failed: ${failures}`);
    process.exit(1);
  }

  console.log("\nAll security leakage checks passed");
}

run();
