const express = require('express');
const { execute } = require('./service');
const app = express();
app.get('/run', (req, res) => {
  const value = req.query.command;
  execute(value);
  res.send('ok');
});
