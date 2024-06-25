require('dotenv').config()
const express = require('express')
const app = express()
const port = process.env.PORT || 4000
const connection = require('./config/database')
const path = require('path');
const middleware = require('./middleware/validations')
const cookieParser = require('cookie-parser');

app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(cookieParser());
// Set the view engine to ejs
app.set('view engine', 'ejs');
// Set the views directory
app.set('views', path.join(__dirname, 'views'));


app.get('/', (req, res) => {
    res.render('register', { error: null })
})
app.get('/login', (req, res) => {
    res.render('login', { error: null })
})

const user = require('./routes/user')
app.use('/api', user)

const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger-output.json');

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

connection()
app.listen(port, (err) => {
    if (!err) {
        console.log(`Application running on http://localhost:${port}`)
    }
    else {
        console.log(err)
        throw err
    }
})