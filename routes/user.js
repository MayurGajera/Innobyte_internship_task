const router = require('express').Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const middleware = require('../middleware/validations')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const path = require('path');

// Configure NodeMailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'mayurghyperlink3336@gmail.com',
        pass: 'ifvsrwgndffculzt'
    }
});

// Function to send confirmation email
async function sendConfirmationEmail(user) {
    const { firstName, email, confirmationUrl } = user;

    // Render the EJS template
    const emailTemplatePath = path.join(__dirname, '..', 'views', 'confirmationEmail.ejs');
    console.log("mailOptions", emailTemplatePath)
    const emailHtml = await ejs.renderFile(emailTemplatePath, { firstName, confirmationUrl });

    // Email options
    const mailOptions = {
        from: 'mayurghyperlink3336@gmail.com',
        to: email,
        subject: 'Please confirm your email address',
        html: emailHtml
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}


router.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        // Define validation rules
        const rules = {
            firstName: 'required',
            lastName: 'required',
            email: 'required|email',
            password: 'required|min:3|max:30'
        };

        // Define custom messages
        const messages = {
            required: ':attr is required',
            email: 'Email must be a valid email address',
            min: 'Password must be at least 3 characters long',
            max: 'Password must be less than or equal to 30 characters long'
        };

        // Assuming middleware.checkValidationRules returns a boolean indicating success/failure
        if (!middleware.checkValidationRules(req.body, res, rules, messages)) {
            return;
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render('register', { message: 'User with given email already exists' });

        }
        const salt = await bcrypt.genSalt(Number(10));
        const hashPassword = await bcrypt.hash(req.body.password, salt);

        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashPassword
        });
        await newUser.save();

        const token = jwt.sign({ user: newUser }, process.env.JWTSECRETKEY, { expiresIn: '1h' })

        // Generate confirmation URL
        const confirmationUrl = `http://localhost:4040/api/verify-email?token=${token}`;
        // Send confirmation email
        await sendConfirmationEmail({ firstName, email, confirmationUrl });
        res.render('message', { message: 'Registration successful! Please check your email to verify your account.' });

    } catch (error) {
        return res.render('register', { message: 'Internal server error' });

    }
})

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const rules = {
            email: 'required|email'
        }
        const messages = {
            required: ':attr is required',
            email: 'Email must be a valid email address'
        }
        if (!middleware.checkValidationRules(req.body, res, rules, messages)) {
            return true;
        }
        const existingUser = await User.findOne({ email: email })
        if (!existingUser) {
            return res.render('login', { error: 'Invalid Email' });

        }
        const validPassword = await bcrypt.compare(
            password, existingUser.password
        )
        if (!validPassword) {
            return res.render('login', { error: 'Invalid Password' });

        }
        const token = jwt.sign({ user: existingUser }, process.env.JWTSECRETKEY, { expiresIn: '1h' })
        // const decoded = jwt.verify(token, process.env.JWTSECRETKEY);
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/api/profile');
        // res.render('userProfile', { user: decoded.user });

    } catch (error) {
        return res.render('login', { error: 'Internal server error' });
    }
})

router.get('/verify-email', async (req, res) => {
    const { token } = req.query

    if (!token) {
        return res.render('message', { message: 'Invalid token' });
    }
    jwt.verify(token, process.env.JWTSECRETKEY, (err, decoded) => {
        if (err) {
            return res.render('message', { message: 'Invalid or expired token' });
        }
        User.updateOne({ _id: decoded.user._id }, { $set: { is_verified: true } })
            .then(result => {
                console.log(result)
                // If the user was found and updated successfully
                if (result.modifiedCount > 0) {
                    res.render('message', { message: 'Email verified successfully!' });
                } else {
                    return res.render('message', { message: 'User not found or already verified.' });
                }
            }).catch(error => {
                console.error('Error updating user:', error);
            })
    })
})

router.post('/logout', async (req, res) => {
    const token = req.cookies.token;
    if (token) {
        res.clearCookie('token');
    }
    res.redirect('/login')
})

// Protected route
router.get('/profile', middleware.verifyToken, (req, res) => {
    res.render('userProfile', { user: req.user });
});

// Update user profile route
router.post('/update_profile', middleware.verifyToken, async (req, res) => {
    try {
        const { firstName, lastName, email } = req.body;
        const userId = req.user._id; // Extract user ID from decoded token

        // Options for findOneAndUpdate
        const options = {
            new: true, // Return the updated document
            runValidators: true // Run validators on update, to ensure new data meets schema requirements
        };

        // Find one user by ID and update
        const updatedUser = await User.findOneAndUpdate(
            { _id: userId },
            { firstName, lastName, email },
            options
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate a new JWT token
        const token = jwt.sign({ user: updatedUser }, process.env.JWTSECRETKEY, { expiresIn: '1h' });

        // Set the new token in the response cookie
        res.cookie('token', token, { httpOnly: true });

        // Respond with updated user data
        res.status(200).json({ message: 'User updated successfully', user: updatedUser });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Change password
router.post('/change_password', middleware.verifyToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const userId = req.user._id; // Extract user ID from decoded token

        // Retrieve the user from the database
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ code: 0, message: 'User not found' });
        }

        // Compare new password with the current password
        const isMatch = await bcrypt.compare(newPassword, user.password);

        if (isMatch) {
            return res.status(400).json({ code: 0, message: 'New password must be different from the current password' });
        }

        // If passwords are different, proceed with password update
        const salt = await bcrypt.genSalt(Number(10));
        const hashPassword = await bcrypt.hash(newPassword, salt);

        // Options for findOneAndUpdate
        const options = {
            new: true,
            runValidators: true
        };

        // Update the user's password
        const updatedUser = await User.findOneAndUpdate(
            { _id: userId },
            { password: hashPassword },
            options
        );

        // Respond with success message
        res.status(200).json({ code: 1, message: 'User Password Changed successfully' });

    } catch (error) {
        console.error('Error updating user password:', error);
        res.status(500).json({ code: 0, message: 'Internal server error' });
    }
});


module.exports = router;