const mongoose = require('mongoose');
module.exports = () => {
    const connectionParams = {
        // useNewUrlParser: true,
        // useUnifiedTopology: true,
    };
    try {
        mongoose.connect(process.env.URL, connectionParams);
        console.log("Connected to database successfully")
    } catch (error) {
        console.log(error)
        console.log("Could not connnect database")
    }
}