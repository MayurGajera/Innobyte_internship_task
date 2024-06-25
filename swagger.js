const swaggerJSDoc = require('swagger-jsdoc');

const swaggerDefinition = {
    openapi: '3.0.0',
    info: {
        title: 'User Registration API',
        version: '1.0.0',
        description: 'API for registering users and sending email verification.',
    },
    servers: [
        {
            url: 'http://localhost:4040', // Replace with your actual server URL
            description: 'Development server',
        },
    ],
};

const options = {
    swaggerDefinition,
    apis: ['./routes/*.js'],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;
