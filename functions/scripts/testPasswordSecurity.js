/* eslint-disable no-console */
const bcrypt = require("bcryptjs");

const users = [
  {username: "alice", password: "CommonPass123!"},
  {username: "bob", password: "CommonPass123!"},
  {username: "charlie", password: "CommonPass123!"},
];

const dictionary = [
  "password",
  "123456",
  "qwerty",
  "letmein",
  "admin",
  "CommonPass123",
  "MyBlog@2026!",
];

const benchmarkRounds = [5, 10, 15];

const benchmark = async (rounds) => {
  const password = "BenchMarkPass123!";
  const samples = [];

  for (let i = 0; i < 3; i += 1) {
    const startedAt = process.hrtime.bigint();
    await bcrypt.hash(password, rounds);
    const endedAt = process.hrtime.bigint();
    samples.push(Number(endedAt - startedAt) / 1e6);
  }

  const averageMs = samples.reduce((acc, n) => acc + n, 0) / samples.length;
  return {rounds, averageMs: Number(averageMs.toFixed(2)), samples};
};

const crackHashWithDictionary = async (hash) => {
  for (const candidate of dictionary) {
    const isMatch = await bcrypt.compare(candidate, hash);
    if (isMatch) {
      return candidate;
    }
  }
  return null;
};

const simulate = async () => {
  console.log("=== Password Security Simulation ===");

  const plaintextDb = users.map((u) => ({
    username: u.username,
    password: u.password,
  }));

  const hashedDb = [];
  for (const user of users) {
    const hash = await bcrypt.hash(user.password, 10);
    const manualSalt = await bcrypt.genSalt(10);
    const manualHash = await bcrypt.hash(user.password, manualSalt);

    hashedDb.push({
      username: user.username,
      hash,
      manualSalt,
      manualHash,
    });
  }

  const uniqueAutoHashes = new Set(hashedDb.map((u) => u.hash)).size;
  const uniqueManualHashes = new Set(hashedDb.map((u) => u.manualHash)).size;

  console.log("\nPlaintext DB sample (breach view):");
  console.log(plaintextDb);

  console.log("\nHashed DB sample (breach view):");
  console.log(hashedDb.map((u) => ({
    username: u.username,
    hash: u.hash,
    saltPreview: u.manualSalt.slice(0, 10) + "...",
    manualHash: u.manualHash,
  })));

  const crackedFromHash = await crackHashWithDictionary(hashedDb[0].hash);

  const lockoutState = {
    maxAttempts: 5,
    failedAttempts: 0,
    locked: false,
  };
  for (let i = 0; i < 5; i += 1) {
    lockoutState.failedAttempts += 1;
    if (lockoutState.failedAttempts >= lockoutState.maxAttempts) {
      lockoutState.locked = true;
    }
  }

  const perf = [];
  for (const rounds of benchmarkRounds) {
    perf.push(await benchmark(rounds));
  }

  const summary = {
    samePasswordUniqueHashes: uniqueAutoHashes === users.length,
    samePasswordUniqueManualSaltHashes: uniqueManualHashes === users.length,
    dictionaryCrackResult: crackedFromHash,
    lockoutAfterFiveFailures: lockoutState.locked,
    performance: perf,
  };

  console.log("\nSimulation Summary:");
  console.log(JSON.stringify(summary, null, 2));

  return summary;
};

simulate().catch((error) => {
  console.error("Simulation failed:", error);
  process.exit(1);
});