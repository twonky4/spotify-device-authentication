'use strict';

module.exports = function () {
	let buf = Buffer.from([]);

	return {
		writeByte: function(val) {
			let b = Buffer.alloc(1);
			b[0] = val;

			buf = Buffer.concat([buf, b]);
		},
		writeInt: function(i) {
			let b = Buffer.alloc(4);
			b.writeUInt32BE(i, 0);
			buf = Buffer.concat([buf, b]);
		},
		write: function(b) {
			buf = Buffer.concat([buf, b]);
		},
		array: function() {
			return buf;
		}
	};
};
