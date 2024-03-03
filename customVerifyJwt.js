const jwt = require('jsonwebtoken');
const User = require('./models/user');

function verifyJWT(req, res, next) {
	const token =
		req.headers.authorization && req.headers.authorization.split(' ')[1];

	if (!token) {
		return res.status(401).json({ error: 'Unauthorized: Missing token' });
	}

	jwt.verify(token, process.env.TOKEN_KEY, async (err, decoded) => {
		if (err) {
			return res
				.status(401)
				.json({ message: 'Unauthorized: Invalid token' });
		}

		const user = await User.findById(decoded.user._id);
		req.authUser = user;

		next();
	});
}

module.exports = verifyJWT;
