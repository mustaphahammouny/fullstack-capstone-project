
/*jshint esversion: 8 */
const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const dotenv = require('dotenv');
const pino = require('pino');

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
            logger.error('Email already exists');
            return res.status(400).json({ error: 'Email already exists!' });
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
        return res.json({ authtoken, email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();

        // Task 2: Access MongoDB collection
        const collection = db.collection('users');

        // Task 3: Check for user credentials in database
        const user = await collection.findOne({ email: req.body.email });

        // Task 7: Send appropriate message if user not found
        if (!user) {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found!' });
        }

        // Task 4: Task 4: Check if the password matches the encrypyted password and send appropriate message on mismatch
        let result = await bcryptjs.compare(req.body.password, user.password);

        if (!result) {
            logger.error('Passwords do not match');
            return res.status(404).json({ error: 'Wrong pasword!' });
        }

        // Task 5: Fetch user details from database
        const userName = user.firstName;
        const userEmail = user.email;

        // Task 6: Create JWT authentication if passwords match with user._id as payload
        jwt.sign(
            { user: { id: user._id.toString() } },
            JWT_SECRET
        );

        logger.info('User logged in successfully');
        return res.json({ authtoken, userName, userEmail });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error rrrrrrrrr');
    }
});

router.put('/update', async (req, res) => {
    // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        // Task 3: Check if `email` is present in the header and throw an appropriate error message if not present.
        const email = req.headers.email;
        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({ error: "Email not found in the request headers" });
        }

        // Task 4: Connect to MongoDB
        const db = await connectToDatabase();
        const collection = db.collection("users");

        // Task 5: find user credentials in database
        const existingUser = await collection.findOne({ email: email });
        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }

        // Task 6: update user credentials in database
        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();

        const updatedUser = await collection.findOneAndUpdate(
            { email: email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        // Task 7: create JWT authentication using secret key from .env file
        const authtoken = jwt.sign(
            { user: { id: updatedUser._id.toString() } },
            JWT_SECRET
        );

        logger.info('User updated successfully');
        return res.json({ authtoken });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;
