'use strict';

const Shannon = require('shannon');

function byteToBuffer(val) {
	let buf = new Buffer(1);
	buf.writeUInt8(val, 0);
	return buf;
}

function shortToBuffer(val) {
	let buf = new Buffer(2);
	buf.writeUInt16BE(val, 0);
	return buf;
}

function intToBuffer(val) {
	let buf = new Buffer(4);
	buf.writeUInt32BE(val, 0);
	return buf;
}

module.exports = function (sendKey, recvKey) {
    let sendCipher = new Shannon(sendKey);
    let sendNonce = 0;

    let recvCipher = new Shannon(recvKey);
    let recvNonce = 0;

	return {
		sendEncoded: function(socket, cmd, payload) {
            sendCipher.nonce(intToBuffer(sendNonce++));

            let buffer = Buffer.concat([byteToBuffer(cmd), shortToBuffer(payload.length), payload]);

            let bytes = sendCipher.encrypt(buffer);

            let mac = sendCipher.finish(Buffer.alloc(4));

            socket.write(bytes);
            socket.write(mac);
		},
		receiveEncoded: function(data) {
			let ret = {
				complete: false
            };
            recvCipher.nonce(intToBuffer(recvNonce));

            let headerBytes = data.slice(0, 3);
            headerBytes = recvCipher.decrypt(headerBytes);
            if(headerBytes.length != 3) {
            	return ret;
            }

            let cmd = headerBytes.readUInt8(0);
            ret.cmd = cmd;
            
            let payloadLength = ((headerBytes.readUInt8(1) << 8) | (headerBytes.readUInt8(2) & 0xFF));

            ret.payloadLength = payloadLength;
            ret.next = data.slice(payloadLength + 3 + 4, data.length);

            let payloadBytes = data.slice(3, payloadLength + 3);
            if(payloadBytes.length != payloadLength) {
            	return ret;
            }
            payloadBytes = recvCipher.decrypt(payloadBytes);
            ret.payloadBytes = payloadBytes;

            let mac = data.slice(payloadLength + 3, payloadLength + 3 + 4);
            if(mac.length != 4) {
            	return ret;
            }
            ret.complete = true;

            let expectedMac = recvCipher.finish(Buffer.alloc(4));
            if (Buffer.compare(mac, expectedMac) != 0) {
            	throw new Error("MACs don't match!");
            }

            recvNonce++;
            return ret;
	    }
	};
};
