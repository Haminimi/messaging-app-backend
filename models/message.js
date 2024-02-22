const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const MessageSchema = new Schema({
	chat: { type: Schema.Types.ObjectId, ref: 'Chat', required: true },
	message: {
		textMessage: {
			type: String,
			required: function () {
				return this.message.imageMessage ? false : true;
			},
			message: 'Either textMessage or imageMessage is required.',
		},
		imageMessage: {
			type: String,
			required: function () {
				return this.message.textMessage ? false : true;
			},
			message: 'Either textMessage or imageMessage is required.',
		},
	},
	author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
	timestamp: { type: Number, required: true },
});

module.exports = mongoose.model('Message', MessageSchema);
