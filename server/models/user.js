const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//define model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true, required: [true, 'must provide username/email'] },
  password: { type: String, minlength: 6, maxlength: 40 }
});

//on save hook, encrypt password
userSchema.pre('save', function(next) {
  const user = this;

  bcrypt.genSalt(10, function(saltError, salt) {
    if (saltError) return next(saltError);

    bcrypt.hash(user.password, salt, null, function(hashError, hash) {
      if (hashError) return next(hashError);

      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function (candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) return callback(err);

    callback(null, isMatch);
  });
};

//create model class
const ModelClass = mongoose.model('User', userSchema);

//export the model
module.exports = ModelClass;
