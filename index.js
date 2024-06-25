require('dotenv').config() // Load environment variables from .env file
const express = require('express')
const app = express()
const port = process.env.PORT || 4000 // Set the port from environment variable or default to 4000
const connection = require('./config/database')// Import database connection function
const path = require('path');
const middleware = require('./middleware/validations') // Import custom middleware for validation
const user = require('./routes/user')  // Import user routes
const cookieParser = require('cookie-parser');
const swaggerUi = require('swagger-ui-express');


app.use(express.json()) // Parse JSON bodies
app.use(express.urlencoded({ extended: false })) // Parse URL-encoded bodies
app.use(cookieParser());


app.set('view engine', 'ejs'); // Set the view engine to ejs
app.set('views', path.join(__dirname, 'views')); // Set the views directory

// Render registration form
app.get('/api/signup', (req, res) => {
    res.render('register')
})

// Render login form
app.get('/api/login', (req, res) => {
    res.render('login')
})

// Protected route for user profile, verifyToken middleware checks authentication
app.get('/profile', middleware.verifyToken, (req, res) => {
    res.render('userProfile', { user: req.user });
});
app.use('/api', user)  // Mount user routes under /api

// Swagger API documentation setup
const swaggerDocument = require('./swagger.json'); // Load Swagger JSON file
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument)); // Serve Swagger UI

connection() // Initialize database connection

// Start server
app.listen(port, (err) => {
    if (!err) {
        console.log(`Application running on http://localhost:${port}`)
    }
    else {
        console.log(err)
        throw err
    }
})