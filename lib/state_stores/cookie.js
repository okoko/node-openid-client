const crypto = require('crypto');

const { encode } = require('../helpers/base64url');

class CookieStore {
  constructor(name, keys, maxAge = 60 * 60, sameSite = true) {
    if (typeof name === 'string') {
      this.name = name;
    } else {
      this.name = `oidc.${encode(name.issuer.issuer)}`;
    }
    this.keys = keys;
    this.maxAge = maxAge;
    this.sameSite = sameSite;
  }

  save(req, state, params) {
    if (!req.cookies) {
      throw new TypeError('authentication requires cookie support');
    }
    const res = params.response || req.res;
    delete params.response;

    const stateStr = JSON.stringify(state);
    const { key, iv } = this.keys[0];
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let stateCipher = cipher.update(stateStr, 'utf8', 'hex');
    stateCipher += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    const encrypted = `${stateCipher}.${authTag}`;

    const options = { maxAge: this.maxAge * 1000, httpOnly: true };

    if (this.sameSite) {
      options.sameSite = 'none';
      options.secure = true; // Browser may ignore SameSite=None if not true
    }

    res.cookie(this.name, encrypted, options);
  }

  load(req, options) {
    const res = options.response || req.res;
    if (!res) {
      throw new TypeError('authentication requires response object');
    }

    const cookie = req.cookies[this.name];
    if (!cookie) return undefined;

    const parts = cookie.split('.');
    if (parts.length !== 2) throw new Error('invalid cookie');

    const authTag = Buffer.from(parts[1], 'hex');

    let stateStr;
    if (this.keys.some(({ key, iv }) => {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      stateStr = decipher.update(parts[0], 'hex', 'utf8');
      try {
        stateStr += decipher.final('utf8');
      } catch (_) {
        return false; // Did not decipter using these keys
      }
      return true;
    })) {
      res.clearCookie(this.name);
      return JSON.parse(stateStr);
    }
    return undefined;
  }
}

module.exports = CookieStore;
