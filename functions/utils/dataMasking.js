const SENSITIVE_KEYS = [
  "password",
  "newpassword",
  "currentpassword",
  "token",
  "authorization",
  "cookie",
  "email",
  "totpsecret",
  "secret",
  "code",
];

const maskString = (value) => {
  if (typeof value !== "string") return value;
  if (value.length <= 4) return "****";
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
};

const shouldMask = (key) => SENSITIVE_KEYS.includes(String(key || "").toLowerCase());

const maskData = (input) => {
  if (Array.isArray(input)) {
    return input.map((item) => maskData(item));
  }

  if (input && typeof input === "object") {
    const output = {};
    for (const [key, value] of Object.entries(input)) {
      if (shouldMask(key)) {
        output[key] = "[REDACTED]";
      } else if (value && typeof value === "object") {
        output[key] = maskData(value);
      } else if (typeof value === "string" && key.toLowerCase().includes("email")) {
        output[key] = maskString(value);
      } else {
        output[key] = value;
      }
    }
    return output;
  }

  return input;
};

module.exports = {
  maskData,
};
