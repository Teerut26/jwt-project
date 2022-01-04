const jwt = require("jsonwebtoken");
const TokenExp = require("../model/tokenExp");

const config = process.env;

const verifyToken = async (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) {
    return res.status(200).send({
      error: true,
      message: "A token is required for authentication",
    });
  }

  const tokenExp = await TokenExp.findOne({ token });

  if (tokenExp) {
    return res.status(200).send({
      error: true,
      message: "Invalid Token",
    });
  }

  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    return res.status(200).send({
      error: true,
      message: "Invalid Token",
    });
  }
  return next();
};

module.exports = verifyToken;
