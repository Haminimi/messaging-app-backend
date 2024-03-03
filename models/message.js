const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const MessageSchema = new Schema({
	chat: { type: Schema.Types.ObjectId, ref: 'Chat', required: true },
	message: { type: String, required: true },
	author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
	timestamp: { type: Number, required: true },
});

module.exports = mongoose.model('Message', MessageSchema);
