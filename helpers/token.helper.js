const jwt = require("jsonwebtoken");

const tokenHelper = {
  generateToken(expiresIn = '2h') {
    return jwt.sign(
      { foo: 'bar' },
      process.env.TOKEN_KEY,
      {
        // expiresIn: 15,
        expiresIn: expiresIn,
      }
    );
  },
  getToken(req) {
    return req.headers["authorization"].split(" ")[1]
  },
  verifyToken(token) {
    return jwt.verify(token, process.env.TOKEN_KEY, function(error, decodedData) {
      if (error) {
        console.log('tokenHelper verifyToken', error);
        return false;
      }
      console.log('tokenHelper verifyToken OK');
      return true;
    });

  },
}

module.exports = tokenHelper;
