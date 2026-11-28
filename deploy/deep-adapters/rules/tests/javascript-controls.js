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

const fs = require("fs");
function pathBad(req) {
  const value = req.query.path;
  const alias = value;
  if (alias) {
    // ruleid: javascript.request-path-traversal
    return fs.readFileSync(alias);
  }
}
function pathNestedBad(req) {
  const value = req.params.path;
  try {
    // ruleid: javascript.request-path-traversal
    return fs.promises.readFile(value);
  } catch (error) { throw error; }
}
function callbackReadBad(req, callback) {
  const value = req.query.path;
  const alias = value;
  // ruleid: javascript.request-path-traversal
  return fs.readFile(alias, callback);
}
function callbackReadFixedSafe(req, callback) {
  const value = req.query.contents;
  // ok: javascript.request-path-traversal
  return fs.readFile("fixed.txt", callback);
}
function callbackReadReboundSafe(req, callback) {
  let value = req.query.path;
  value = "fixed.txt";
  // ok: javascript.request-path-traversal
  return fs.readFile(value, callback);
}
function pathSafe(req) {
  const value = req.body.contents;
  // ok: javascript.request-path-traversal
  fs.writeFileSync("fixed.txt", value);
}
function pathRebound(req) {
  let value = req.query.path;
  value = "fixed.txt";
  // ok: javascript.request-path-traversal
  return fs.readFileSync(value);
}

function streamPathBad(req) {
  const value = req.body.path;
  // ruleid: javascript.request-path-traversal
  return fs.createReadStream(value);
}

function htmlTemplateBad(req, res) {
  // ruleid: javascript.request-html-injection
  res.send(`API Running...${req.query.content}`);
}

function htmlDirectBad(req, res) {
  const value = req.query.name;
  // ruleid: javascript.request-html-injection
  res.send(value);
}

function htmlBuiltVariableBad(req, res) {
  const page = "<p>" + req.params.id + "</p>";
  // ruleid: javascript.request-html-injection
  res.send(page);
}

function jsonObjectSafe(req, res) {
  const update = lookupUpdate(req.query);
  // ok: javascript.request-html-injection
  res.send(update);
}

function binaryMediaSafe(req, res) {
  const video = renderPreview(req.query.id);
  res.set("Content-Type", "video/mp4");
  // ok: javascript.request-html-injection
  res.send(video);
}

function queuedObjectSafe(req, res, queue) {
  // ok: javascript.request-html-injection
  res.send(queue[JSON.stringify(req.query)]);
}

function sqlHelperPlaceholdersSafe(req, db, service) {
  const statement = service.listCommits(req.query.start, req.query.end);
  // ok: javascript.request-sql-injection
  db.query(statement.sql, statement.params);
}

function containedDownloadSafe(req, res, root) {
  const rel = safeRelative(req.query.path, root);
  // ok: javascript.request-path-traversal
  return fs.createReadStream(path.join(root, rel));
}

async function storedDocumentSafe(req, res, Document) {
  const record = await Document.findById(req.params.id);
  // ok: javascript.request-path-traversal
  return fs.readFileSync(path.resolve(record.filePath), "utf-8");
}

function rawMarkdownRenderer(md, Token) {
  md.renderer.rules.paragraph_open = (tokens, index) => {
    // source: javascript.request-html-injection
    const children = tokens[index].children;
    const label = children.reduce((text, child) => text + child.content, "");
    const raw = new Token("html_inline", "", 0);
    // ruleid: javascript.request-html-injection
    raw.content = label;
    return md.renderer.renderInline([raw], {}, {});
  };
}

function rawMarkdownBlock(md, Token) {
  md.renderer.rules.paragraph_open = function (items, index) {
    // source: javascript.request-html-injection
    const label = items[index].content;
    let raw = new Token("html_block", "", 0);
    // ruleid: javascript.request-html-injection
    raw.content = label;
    return md.renderer.render([raw], {}, {});
  };
}

function safeMarkdownRenderer(md, Token) {
  md.renderer.rules.paragraph_open = (tokens, index) => {
    const payload = tokens[index].content;
    const text = new Token("text", "", 0);
    // ok: javascript.request-html-injection
    text.content = payload;
    const escaped = md.utils.escapeHtml(payload);
    const html = new Token("html_inline", "", 0);
    // ok: javascript.request-html-injection
    html.content = escaped;
    const decoration = new Token("html_inline", "", 0);
    // ok: javascript.request-html-injection
    decoration.content = "<span>";
    return md.renderer.renderInline([text, html, decoration], {}, {});
  };
}
