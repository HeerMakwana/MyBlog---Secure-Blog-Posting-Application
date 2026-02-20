const { authenticator } = require('otplib');
const QRCode = require('qrcode');

authenticator.options = {
  digits: 6,
  step: 30,
  window: 1
};

const generateSecret = () => {
  return authenticator.generateSecret();
};

const generateOtpAuthUrl = (username, secret, issuer = 'MyBlog') => {
  return authenticator.keyuri(username, issuer, secret);
};

const generateQRCode = async (otpAuthUrl) => {
  try {
    return await QRCode.toDataURL(otpAuthUrl);
  } catch (error) {
    throw new Error('Failed to generate QR code');
  }
};

const verifyTOTP = (token, secret) => {
  try {
    return authenticator.verify({ token, secret });
  } catch (error) {
    return false;
  }
};

const generateTOTP = (secret) => {
  return authenticator.generate(secret);
};

module.exports = {
  generateSecret,
  generateOtpAuthUrl,
  generateQRCode,
  verifyTOTP,
  generateTOTP
};
