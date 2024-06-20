const swaggerAutogen = require('swagger-autogen')();

const doc = {
    info: {
        title: 'Nodejs + Mngodb API',
        description: 'Description'
    },
    host: 'localhost:4040'
};

const outputFile = './swagger-output.json';
const routes = ['./index.js'];

swaggerAutogen(outputFile, routes, doc).then(() => {
    require('./index.js');
});