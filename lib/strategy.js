/**
 * Module dependencies.
 */
const passport = require("passport-strategy");
const util = require("util");
const lookup = require("./utils").lookup;
const LitJsSdk = require("lit-js-sdk");

/**
 * `Strategy` constructor.
 *
 * The Lit Protocol authentication strategy authenticates requests based on the
 * JWT submitted via a POST request.
 *
 * Applications must supply a `verify` callback which accepts an `address` param
 * and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurred, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `jwtField`  field name where the jwt is found, defaults to `jwt`
 *   - `baseUrlField`  field name where the baseUrl is found, defaults to `baseUrl`
 *   - `pathField`  field name where the path is found, defaults to `path`
 *   - `extraDataField`  field name where the extraData is found, defaults to `extraData`
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Example:
 *
 *     passport.use(new LitProtocolStrategy(
 *       function(address, message, signed, done) {
 *         User.findOne({ address: address }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new TypeError("LitProtocolStrategy requires a verify callback");
  }

  this._jwtField = options.jwtField || "jwt";
  this._baseUrlField = options.baseUrlField || "baseUrl";
  this._pathField = options.pathField || "path";
  this._extraDataField = options.extraDataField || "extraData";

  passport.Strategy.call(this);
  this.name = "litProtocol";
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  const jwt =
    lookup(req.body, this._jwtField) || lookup(req.query, this._jwtField);
  const baseUrl =
    lookup(req.body, this._baseUrlField) ||
    lookup(req.query, this._baseUrlField);
  const path =
    lookup(req.body, this._pathField) || lookup(req.query, this._pathField);
  const extraData =
    lookup(req.body, this._extraDataField) ||
    lookup(req.query, this._extraDataField);

  if (!jwt || !baseUrl || !path || !extraData) {
    return this.fail(
      { message: options.badRequestMessage || "Missing credentials" },
      400
    );
  }

  const { verified, payload } = LitJsSdk.verifyJwt({ jwt });
  const address = payload.sub;

  if (
    payload.baseUrl !== baseUrl ||
    payload.path !== path ||
    payload.extraData !== extraData
  ) {
    return this.fail(
      {
        message:
          options.badRequestMessage ||
          "Ooops. JWT payload does not match requested resource.",
      },
      400
    );
  }

  if (!verified) {
    return this.fail(
      {
        message:
          options.badRequestMessage ||
          "Ooops. You don't have access to this resource.",
      },
      400
    );
  }

  const self = this;

  function callback(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  }

  try {
    if (self._passReqToCallback) {
      this._verify(req, address, callback);
    } else {
      this._verify(address, callback);
    }
  } catch (ex) {
    return self.error(ex);
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
