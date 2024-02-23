const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const User = require('../models/user');

router.post(
	'/',
	[
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

						const user = new User({
							firstName: req.body.first,
							lastName: req.body.last,
							email: req.body.email,
							password: hashedPassword,
							about: req.body.about,
							avatar: req.body.avatar,
						});
						await user.save();
						res.json({ success: true });
					}
				);
			}
		} catch (err) {
			return next(err);
		}
	}
);

module.exports = router;
