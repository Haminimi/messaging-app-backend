const passport = require('passport');
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const User = require('./models/user');

passport.use(
	new JWTStrategy(
		{
			jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
			secretOrKey: process.env.TOKEN_KEY,
		},
		async (jwtPayload, done) => {
			try {
				const user = await User.findById(jwtPayload.id);
				if (user) {
					return done(null, user);
				} else {
					return done(null, false);
				}
			} catch (err) {
				return done(err);
			}
		}
	)
);
