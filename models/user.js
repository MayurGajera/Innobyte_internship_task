const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    is_verified: { type: Boolean, default: false }
});

// userSchema.methods.generateAuthToken = function () {
//     const token = jwt.sign({ _id: this._id }, process.env.JWTSECRETKEY, { expiresIn: '7d' })
//     return token
// }
const User = mongoose.model('user', userSchema)



module.exports = User 