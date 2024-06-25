const mongoose = require('mongoose');
module.exports = () => {
    const connectionParams = {
        // useNewUrlParser: true,
        // useUnifiedTopology: true,
    };
    // Attempt to connect to MongoDB using environment variable URL
    try {
        mongoose.connect(process.env.URL, connectionParams); // Connect to MongoDB using URL from environment variables
        console.log("Connected to database successfully")
    } catch (error) {
        console.log(error)
        console.log("Could not connnect database")
    }
}