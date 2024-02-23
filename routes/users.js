const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const User = require('../models/user');
const upload = require('../upload');
const jwt = require('jsonwebtoken');

router.post(
	'/',
	[
		upload.single('avatar'),

		body('first', 'First name must not be empty.')
			.trim()
			.notEmpty()
			.escape(),
		body('last', 'Last name must not be empty.').trim().notEmpty().escape(),
		body('email')
			.trim()
			.notEmpty()
			.escape()
			.withMessage('Email must not be empty.')
			.isEmail()
			.withMessage(
				'Email is not in a valid form. It should look something like: johndoe@gmail.com.'
			)
			.custom(async (value) => {
				const user = await User.findOne({ email: value });
				if (user) {
					throw new Error('Email already in use.');
				}
			})
			.normalizeEmail(),
		body('password')
			.trim()
			.blacklist('<>&\'"/')
			.isStrongPassword({
				minLength: 8,
				minLowercase: 1,
				minUppercase: 1,
				minNumbers: 1,
				minSymbols: 1,
				returnScore: false,
			})
			.withMessage(
				'Must contain at least one uppercase and lowercase letter, one digit, one special character (@$!%*#?), and be at least 8 characters long.'
			),
		body('confirmPassword', 'Passwords do not match.').custom(
			(value, { req }) => {
				return value === req.body.password;
			}
		),
		body('about').escape(),
		body('avatar').custom((value, { req }) => {
			if (!req.file) {
				return true;
			}
			if (!req.file.mimetype.startsWith('image/')) {
				throw new Error('You should submit an image file.');
			}
		}),
	],
	async (req, res, next) => {
		try {
			const errors = validationResult(req);

			if (!errors.isEmpty()) {
				res.json({ errors });
			} else {
				bcrypt.hash(
					req.body.password,
					10,
					async (err, hashedPassword) => {
						if (err) {
							next(err);
						}

						const uploadedFile = req.file;
						const filePath = uploadedFile
							? '/uploads/' + uploadedFile.filename
							: '';

						const user = new User({
							firstName: req.body.first,
							lastName: req.body.last,
							email: req.body.email,
							password: hashedPassword,
							about: req.body.about,
							avatar: filePath,
						});
						const createdUser = await user.save();
						res.json({ success: true, createdUser });
					}
				);
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.post('/login', async (req, res, next) => {
	console.log(req.body);
	passport.authenticate('local', async (error, user, info) => {
		try {
			console.log(user);
			console.log(info);

			req.login(user, async (error) => {
				if (error) {
					return res.status(500).json({
						message: 'Something is wrong',
						error: error || 'internal server error',
					});
				}
				const token = jwt.sign({ user }, process.env.TOKEN_KEY);
				return res.json({ success: true, user, token });
			});
		} catch (error) {
			return next(error);
		}
	})(req, res, next);
});

module.exports = router;
