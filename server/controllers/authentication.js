const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function (req, res, next) {
  res.send({ token: tokenForUser(req.user) });
};

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password' });
  }

  User.findOne({ email: email }, function(findErr, existingUser) {
    if (findErr) { return next(findErr); }

    if (existingUser) {
      return res.status(422).send({ error: 'Email already in use' });
    }

    const user = new User({
      email: email,
      password: password
    });

    user.save(function(saveErr, newUser) {
      if (saveErr) { return next(saveErr); }

      res.send({ token: tokenForUser(newUser), user: newUser });
    });
  });
};
