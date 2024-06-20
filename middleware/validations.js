
const Validator = require('Validator')
const jwt = require('jsonwebtoken')
const validations = {
    checkValidationRules: function (req, res, rules, messages) {
        var v = Validator.make(req, rules, messages)
        if (v.fails()) {
            const errors = v.getErrors();
            let error = '';
            for (let key in errors) {
                error = errors[key][0];
                break;
            }
            res.json({
                code: 0,
                message: error
            })
            return false
        } else {
            return true;
        }
    },


    // Middleware to verify JWT
    verifyToken: function (req, res, next) {
        // console.log('first', req.cookies)
        const token = req.cookies.token;

        if (!token)
            res.redirect('/login')
        try {
            const verified = jwt.verify(token, process.env.JWTSECRETKEY);
            if (verified.user.is_verified == false) {
                res.render('login', { error: "User not verified" })
            }
            req.user = verified.user;
            next();
        } catch (err) {
            res.status(400).json({ message: 'Invalid Token' });
        }
    }
}

module.exports = validations