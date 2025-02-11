const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const dotenv = require('dotenv');
const pino = require('pino');

const app = express();
const logger = pino();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

dotenv.config();

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();

        // Task 2: Access MongoDB collection
        const collection = db.collection('users');

        const email = req.body.email;

        //Task 3: Check for existing email
        const existingUser = await collection.findOne({ email: email });

        if (existingUser) {
            res.status(400).json({ message: 'Email already exists!' });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);

        //Task 4: Save user details in database
        const user = await collection.insertOne({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: email,
            password: hash,
            createdAt: new Date(),
        });

        //Task 5: Create JWT authentication with user._id as payload
        const authtoken = jwt.sign(
            { user: { id: user.insertedId } },
            JWT_SECRET
        );

        logger.info('User registered successfully');

        res.json({ authtoken, email });
    } catch (e) {
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;
