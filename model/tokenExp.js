const mongoose = require("mongoose");

const tokenExpSchema = new mongoose.Schema({
  token: { type: String },
});

module.exports = mongoose.model("tokenExp", tokenExpSchema);
