const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { body, check, validationResult } = require('express-validator');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const verifyJWT = require('../customVerifyJwt');
const upload = require('../upload');
const { ObjectId } = require('mongodb');
const User = require('../models/user');
const Chat = require('../models/chat');
const Message = require('../models/message');

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

router.get('/isUserAuth', verifyJWT, async (req, res, next) => {
	res.json({ success: true, user: req.authUser });
});

router.post(
	'/:userId/chats/:chatId/messages',
	[
		passport.authenticate('jwt', { session: false }),
		body('message', 'Message must not be empty.')
			.trim()
			.isLength({ min: 1 })
			.blacklist('<>&/'),
	],
	async (req, res, next) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				const message = errors.errors[0].msg;
				return res.json({ error: message });
			} else {
				const chatId = req.params.chatId;
				const userId = req.params.userId;
				const authUserId = req.user._id;
				if (userId === authUserId.toString()) {
					const chat = await Chat.findById(chatId).populate(
						'messages'
					);
					const isUserInChat = chat.users.some((user) => {
						return user._id.toString() === authUserId.toString();
					});

					if (isUserInChat) {
						const newMessage = new Message({
							chat: chatId,
							message: req.body.message,
							author: authUserId,
							timestamp: Date.now(),
						});

						const createdMessage = await newMessage.save();
						const newChat = new Chat({
							...chat,
							users: chat.users,
							messages: [...chat.messages, createdMessage._id],
							_id: chatId,
						});

						const updatedChat = await Chat.findByIdAndUpdate(
							chatId,
							newChat,
							{ new: true }
						);
						const populatedChat = await Chat.populate(updatedChat, [
							{ path: 'messages', populate: { path: 'author' } },
							{
								path: 'users',
								select: 'firstName lastName avatar _id',
							},
						]);
						return res.json({
							success: true,
							chat: populatedChat,
						});
					} else {
						return res.status(401).json({
							error: 'You are not authorized.',
						});
					}
				} else {
					return res
						.status(401)
						.json({ error: 'You are not authorized.' });
				}
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.get(
	'/:userId/chats/:chatId',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const chatId = req.params.chatId;
			const userId = req.params.userId;
			const authUserId = req.user._id;
			if (userId === authUserId.toString()) {
				const chat = await Chat.findById(chatId)
					.populate({
						path: 'messages',
						populate: { path: 'author' },
					})
					.populate({
						path: 'users',
						select: 'firstName lastName avatar _id',
					});
				const isUserInChat = chat.users.some((user) => {
					return user._id.toString() === authUserId.toString();
				});
				if (isUserInChat) {
					return res.json({
						success: true,
						chat,
					});
				} else {
					return res
						.status(401)
						.json({ error: 'You are not authorized.' });
				}
			} else {
				return res
					.status(401)
					.json({ error: 'You are not authorized.' });
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.get(
	'/:userId/chats',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const userId = req.params.userId;
			const authUserId = req.user._id;
			if (userId === authUserId.toString()) {
				const chats = await Chat.find({ users: authUserId })
					.populate({
						path: 'users',
						select: 'firstName lastName avatar _id',
					})
					.populate('messages');
				return res.json({
					success: true,
					chats,
				});
			} else {
				return res
					.status(401)
					.json({ error: 'You are not authorized.' });
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.post(
	'/:userId/chats',
	[
		passport.authenticate('jwt', { session: false }),
		check('users')
			.isLength({ min: 2 })
			.withMessage('The users array must have at least two elements.'),
	],
	async (req, res, next) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				const message = errors.errors[0].msg;
				return res.json({ error: message });
			} else {
				const userId = req.params.userId;
				const authUserId = req.user._id;
				if (userId === authUserId.toString()) {
					const { users: userIDs } = req.body;
					const existingChat = await Chat.findOne({
						users: { $all: [...userIDs] },
					});

					if (existingChat) {
						res.json({
							success: true,
							chat: existingChat,
						});
					} else {
						const newChat = new Chat({
							users: req.body.users,
							messages: [],
						});
						const chat = await newChat.save();
						res.json({
							success: true,
							chat,
						});
					}
				} else {
					res.status(401).json({ error: 'You are not authorized.' });
				}
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.get(
	'/:userId/friends',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const userId = req.params.userId;
			const authUserId = req.user._id;
			if (userId === authUserId.toString()) {
				const user = await User.findById(authUserId)
					.populate('friends')
					.exec();
				const friends = user.friends;
				const filteredFriends = friends.map((friend) => {
					const sanitizedFriend = {
						first: friend.firstName,
						last: friend.lastName,
						avatar: friend.avatar,
						_id: friend._id,
					};
					return sanitizedFriend;
				});

				return res.json({
					success: true,
					friends: filteredFriends,
				});
			} else {
				res.status(401).json({ error: 'You are not authorized.' });
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.post('/:userId/friends', verifyJWT, async (req, res, next) => {
	try {
		const userId = req.params.userId;
		const authUserId = req.authUser._id;
		const newFriendId = req.body.friend;
		const newFriendObjectId = new ObjectId(newFriendId);
		if (userId === authUserId.toString()) {
			const user = await User.findById(authUserId).exec();
			const friends = user.friends;
			let updatedData;
			if (friends.includes(newFriendObjectId)) {
				updatedData = new User({
					...user,
					_id: authUserId,
					friends: friends.filter((friend) => {
						if (friend !== null) {
							friend.toString() !== newFriendObjectId.toString();
						}
					}),
				});
			} else {
				updatedData = new User({
					...user,
					_id: authUserId,
					friends: [...user.friends, newFriendId],
				});
			}
			const updatedUser = await User.findByIdAndUpdate(
				authUserId,
				updatedData,
				{ new: true }
			);
			const { password, ...sanitizedUser } = updatedUser._doc;
			return res.json({
				success: true,
				updatedUser: sanitizedUser,
			});
		} else {
			res.status(401).json({ error: 'You are not authorized.' });
		}
	} catch (err) {
		console.error(err);
	}
});

router.get(
	'/:userId',
	passport.authenticate('jwt', { session: false }),
	async (req, res, next) => {
		try {
			const authUserId = req.user._id.toString();
			const userId = req.params.userId;
			const user = await User.findById(userId).exec();
			if (authUserId === userId) {
				const { password, ...userData } = user._doc;
				res.json({ success: true, user: userData });
			} else {
				const { email, password, friends, ...userData } = user._doc;
				res.json({ success: true, user: userData });
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.put(
	'/:userId',
	[
		passport.authenticate('jwt', { session: false }),
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
				const authUserId = req.user._id;
				const userId = req.params.userId;
				if (userId === authUserId.toString()) {
					const user = await User.findById(authUserId);

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
						friends: user.friends,
						_id: req.body._id,
					});

					const updated = await User.findByIdAndUpdate(
						req.body._id,
						newData,
						{ new: true }
					);

					const { password, ...updatedUser } = updated._doc;
					return res.json({ success: true, updatedUser });
				} else {
					res.status(401).json({ error: 'You are not authorized.' });
				}
			}
		} catch (err) {
			return next(err);
		}
	}
);

router.post('/login', async (req, res, next) => {
	try {
		const loginData = req.body;

		const user = await User.findOne({ email: loginData.email });
		if (!user) {
			res.status(401).json({ message: 'Incorrect email' });
		}

		const match = await bcrypt.compare(loginData.password, user.password);
		if (!match) {
			res.status(401).json({ message: 'Incorrect password.' });
		}

		const token = jwt.sign({ user }, process.env.TOKEN_KEY, {
			expiresIn: 86400,
		});
		const { password, ...userWithoutPassword } = user._doc;
		return res.json({
			success: true,
			user: userWithoutPassword,
			token,
		});
	} catch (error) {
		return next(error);
	}
});

module.exports = router;
