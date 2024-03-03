const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const createError = require('http-errors');
const cors = require('cors');

require('dotenv').config();

const mongoConfig = require('./mongoConfig');

const usersRouter = require('./routes/users');

const app = express();

require('./passportJwt');

const corsOptions = {
	origin: process.env.FRONTEND_URL,
	optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

if (process.env.NODE_ENV === 'development') {
	app.use(logger('dev'));
}
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/users', usersRouter);
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.use(function (req, res, next) {
	next(createError(404));
});

app.use(function (err, req, res, next) {
	res.status(err.status || 500).json({ error: err.message });
});

module.exports = app;
