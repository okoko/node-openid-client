const Issuer = require('./issuer');
const { OPError, RPError } = require('./errors');
const Registry = require('./issuer_registry');
const Strategy = require('./passport_strategy');
const CookieStore = require('./state_stores/cookie');
const SessionStore = require('./state_stores/session');
const TokenSet = require('./token_set');
const { CLOCK_TOLERANCE, HTTP_OPTIONS } = require('./helpers/consts');
const generators = require('./helpers/generators');
const { setDefaults } = require('./helpers/request');

module.exports = {
  Issuer,
  Registry,
  Strategy,
  CookieStore,
  SessionStore,
  TokenSet,
  errors: {
    OPError,
    RPError,
  },
  custom: {
    setHttpOptionsDefaults: setDefaults,
    http_options: HTTP_OPTIONS,
    clock_tolerance: CLOCK_TOLERANCE,
  },
  generators,
};
