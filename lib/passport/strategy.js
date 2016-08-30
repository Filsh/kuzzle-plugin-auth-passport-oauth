var
  refresh = require('passport-oauth2-refresh');

/**
 * Interface to passportjs
 *
 * @param {Object} context - Kuzzle Plugin context
 * @param {Object} config - this plugin's current configuration
 */
module.exports = function (context, config) {
  this.config = config;
  this.context = context;

  /**
   * Initializes the configured strategies and load them to passportjs
   */
  this.init = function () {
    Object.keys(this.config.strategies).forEach(key => {
      var
        strategy,
        Strategy;

      if (!this.config.strategies[key].credentials) {
        return console.error(`Error loading strategy [${key}]: no credentials provided`);
      }

      try {
        Strategy = require('passport-' + key).Strategy;
      } catch (err) {
        /*eslint no-console: 0*/
        return console.error(`Error loading strategy [${key}]: ${err.message}`);
      }

      strategy = new Strategy(this.config.strategies[key].credentials, this.verify.bind(this));
      this.context.accessors.passport.use(strategy);

      try {
        refresh.use(strategy);
      } catch (err) {
        /*eslint no-console: 0*/
        console.error(`Error refreshing strategy [${key}]: ${err.message}`);
      }
    });
  };

  this.verify = (accessToken, refreshToken, profile, done) => {
    var
      userProfile = this.config.defaultProfile || 'default',
      idAttribute = this.config.defaultIdAttribute || 'name',
      user = {},
      persist = {},
      _get = (obj, path) => path.split('.').reduce((obj, i) => !obj ? null : obj[i], obj);

    if (this.config.strategies[profile.provider].persist) {
      persist = this.config.strategies[profile.provider].persist;

      Object.keys(persist).forEach(attr => {
        if (persist[attr]) {
          user[attr] = _get(profile._json, persist[attr]);
        }
      });
    }

    if(user[idAttribute]) {
      this.context.accessors.users.load(user[idAttribute])
        .then(userObject => {
          if (userObject !== null) {
            return done(null, userObject);
          }

          return this.context.accessors.users.create(user[idAttribute], userProfile, user)
            .then(() => done(null, user));
        })
        .catch(err => done(err));
    } else {
      done(new this.context.errors.UnauthorizedError('Login failed'));
    }
  };
};
