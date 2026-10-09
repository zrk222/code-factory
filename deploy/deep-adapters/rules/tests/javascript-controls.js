const child_process = require("child_process");

function commandBad(req) {
  const value = req.query.command;
  const alias = value;
  if (alias) {
    try {
      // ruleid: javascript.request-command-injection
      child_process.exec(alias);
    } catch (error) {
      throw error;
    }
  }
}

function commandSafe(req) {
  const value = req.query.name;
  // ok: javascript.request-command-injection
  child_process.execFile("echo", [value]);
}

function sqlBad(req, db) {
  const value = req.params.name;
  const query = "SELECT * FROM users WHERE name='" + value + "'";
  // ruleid: javascript.request-sql-injection
  db.query(query);
}

function sqlSafe(req, db) {
  const value = req.params.name;
  // ok: javascript.request-sql-injection
  db.query("SELECT * FROM users WHERE name=?", [value]);
}

function htmlBad(req, res) {
  const value = req.body.name;
  // ruleid: javascript.request-html-injection
  res.send("<h1>" + value + "</h1>");
}

function htmlSafe(req, res) {
  // ok: javascript.request-html-injection
  res.send("<h1>Static content</h1>");
}

function commandRebound(req) {
  let value = req.query.command;
  value = "echo safe";
  // ok: javascript.request-command-injection
  child_process.exec(value);
}
