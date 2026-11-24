const https = require("https");
// ruleid: javascript.tls-reject-unauthorized-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
function make(insecure) {
  if (insecure) {
    // ok: javascript.tls-reject-unauthorized-disabled
    return new https.Agent({ rejectUnauthorized: false });
  }
  // ok: javascript.tls-reject-unauthorized-disabled
  return new https.Agent({ rejectUnauthorized: true });
}
