const { format } = require('util');

const { encode } = require('../helpers/base64url');

class SessionStore {
  constructor(key) {
    if (typeof key === 'string') {
      this.key = key;
    } else {
      this.key = `oidc:${encode(key.issuer.issuer)}`;
    }
  }

  save(req, state) {
    if (!req.session) {
      throw new TypeError('authentication requires session support');
    }
    req.session[this.key] = state;
  }

  load(req) {
    const sessionKey = this.key;
    const state = req.session[sessionKey];
    if (Object.keys(state || {}).length === 0) {
      throw new Error(format('did not find expected authorization request details in session, req.session["%s"] is %j', sessionKey, state));
    }

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    return state;
  }
}

module.exports = SessionStore;
