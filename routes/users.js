const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const User = require('../models/user');
const upload = require('../upload');
const jwt = require('jsonwebtoken');
const verifyJWT = require('../customVerifyJwt');
const { ObjectId } = require('mongodb');

router.get(
	'/',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const users = await User.find().sort({ firstName: 1 }).exec();
			res.json({ success: true, users });
		} catch (err) {
			return next(err);
		}
	}
);

router.get('/isUserAuth', verifyJWT, (req, res, next) => {
	res.json({ success: true, user: req.authUser });
});

router.get(
	'/:userId',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const userId = req.params.userId;
			const user = await User.findById(userId).exec();
			const { email, password, friends, ...userData } = user._doc;
			res.json({ success: true, user: userData });
		} catch (err) {
			return next(err);
		}
	}
);

router.delete(
	'/:userId',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const authUserId = req.user._id.toString();
			const userId = req.params.userId;
			if (authUserId === userId) {
				await User.findByIdAndDelete(authUserId);
				return res.json({ success: true });
			} else {
				return res.json({ error: 'You are not authorized.' });
			}
		} catch (err) {
			return res.json({ error: err });
		}
	}
);

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
			.normalizeEmail()
			.custom(async (value) => {
				const user = await User.findOne({ email: value });
				if (user) {
					throw new Error('Email already in use.');
				}
			}),
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
				'Password must contain at least one uppercase and lowercase letter, one digit, one special character (@$!%*#?), and be at least 8 characters long.'
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
				const message = errors.errors[0].msg;
				return res.json({ error: message });
			} else {
				bcrypt.hash(
					req.body.password,
					10,
					async (err, hashedPassword) => {
						if (err) {
							next(err);
						}

						let filePath;
						if (!req.file) {
							filePath = '/uploads/user.png';
						} else {
							const avatar = req.file;
							filePath = avatar
								? '/uploads/' + avatar.filename
								: '';
						}
						/* const uploadedFile = req.file;
						const filePath = uploadedFile
							? '/uploads/' + uploadedFile.filename
							: ''; */

						const user = new User({
							firstName: req.body.first,
							lastName: req.body.last,
							email: req.body.email,
							password: hashedPassword,
							about: req.body.about,
							avatar: filePath,
						});
						const createdUser = await user.save();
						return res.json({ success: true, createdUser });
					}
				);
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.put(
	'/edit',
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
			.normalizeEmail()
			.custom(async (value, { req }) => {
				const user = await User.findOne({ email: value });
				if (user && user._id.toString() !== req.body._id) {
					throw new Error('Email already in use.');
				}
			}),
		body('about').escape(),
		body('avatar').custom(function (value, { req }) {
			if (req) {
				if (req.file && !req.file.mimetype.startsWith('image/')) {
					throw new Error('You should submit an image file.');
				}
			}
			return true;
		}),
	],
	async (req, res, next) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				const message = errors.errors[0].msg;
				return res.json({ error: message });
			} else {
				let filePath;
				if (!req.file) {
					filePath = req.body.avatar;
				} else {
					const avatar = req.file;
					filePath = avatar ? '/uploads/' + avatar.filename : '';
				}

				const newData = new User({
					firstName: req.body.first,
					lastName: req.body.last,
					email: req.body.email,
					about: req.body.about,
					avatar: filePath,
					_id: req.body._id,
				});

				const updated = await User.findByIdAndUpdate(
					req.body._id,
					newData,
					{ new: true }
				);

				const { password, ...updatedUser } = updated._doc;
				return res.json({ success: true, updatedUser });
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.post('/login', async (req, res, next) => {
	console.log(req.body);
	passport.authenticate('local', async (serverError, user, info) => {
		try {
			if (serverError) {
				return res.status(500).json({
					message: 'Internal server error.',
				});
			}

			req.login(user, async (authError) => {
				if (authError) {
					console.error(authError.message); //Failed to serialize user into session
					return res.status(401).json({
						message: info.message, //'Incorrect password.' 'Incorrect email.'
					});
				}
				const { password, ...userData } = user._doc;
				const token = jwt.sign({ userData }, process.env.TOKEN_KEY);
				return res.json({
					success: true,
					user: userData,
					token,
				});
			});
		} catch (error) {
			return next(error);
		}
	})(req, res, next);
});

router.get('/logout', (req, res, next) => {
	req.logout((err) => {
		if (err) {
			return next(err);
		}
		res.json({ success: true });
	});
});

router.post('/:userId/friends', verifyJWT, async (req, res, next) => {
	try {
		const userId = req.params.userId;
		const authUserId = req.authUser.userData._id;
		const newFriendId = req.body.friend;
		const newFriendObjectId = new ObjectId(newFriendId);
		if (userId === authUserId) {
			const user = await User.findById(authUserId).exec();
			const friends = user.friends;
			let newData;
			if (friends.includes(newFriendObjectId)) {
				newData = new User({
					...user,
					_id: authUserId,
					friends: friends.filter(
						(friend) =>
							friend.toString() !== newFriendObjectId.toString()
					),
				});
			} else {
				newData = new User({
					...user,
					_id: authUserId,
					friends: [...user.friends, newFriendId],
				});
			}
			const updatedUser = await User.findByIdAndUpdate(
				authUserId,
				newData,
				{ new: true }
			);
			const { password, ...updatedUserWithoutPassword } =
				updatedUser._doc;
			return res.json({
				success: true,
				updatedUser: updatedUserWithoutPassword,
			});
		} else {
			res.status(401).json({ error: 'You are not authorized.' });
		}
	} catch (err) {
		console.error(err);
	}
});

module.exports = router;
