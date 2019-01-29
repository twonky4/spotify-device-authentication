/* jshint -W097 */
// jshint strict:false
/*jslint node: true */
'use strict';
const protobuf = require("protobufjs");
const request = require('request');
const Promise = require('promise');
const crypto = require('crypto');
const net = require('net');
const uuidv4 = require('uuid/v4');

const Accumulator = require(__dirname + '/accumulator');
const Keys = require(__dirname + '/keys');
const Cipher = require(__dirname + '/cipherpair');

const KeyExchange = protobuf.loadSync(__dirname + '/proto/keyexchange.proto');
const Authentication = protobuf.loadSync(__dirname + '/proto/authentication.proto');

const ClientHello = KeyExchange.lookup('ClientHello');
const BuildInfo = KeyExchange.lookup('BuildInfo');
const Product = KeyExchange.lookup('Product');
const Platform = KeyExchange.lookup('Platform');
const Cryptosuite = KeyExchange.lookup('Cryptosuite');
const LoginCryptoDiffieHellmanHello = KeyExchange.lookup('LoginCryptoDiffieHellmanHello');
const LoginCryptoHelloUnion = KeyExchange.lookup('LoginCryptoHelloUnion');
const APResponseMessage = KeyExchange.lookup('APResponseMessage');
const ClientResponsePlaintext = KeyExchange.lookup('ClientResponsePlaintext');
const LoginCryptoResponseUnion = KeyExchange.lookup('LoginCryptoResponseUnion');
const LoginCryptoDiffieHellmanResponse = KeyExchange.lookup('LoginCryptoDiffieHellmanResponse');
const PoWResponseUnion = KeyExchange.lookup('PoWResponseUnion');
const CryptoResponseUnion = KeyExchange.lookup('CryptoResponseUnion');

const LoginCredentials = Authentication.lookup('LoginCredentials');
const AuthenticationType = Authentication.lookup('AuthenticationType');
const ClientResponseEncrypted = Authentication.lookup('ClientResponseEncrypted');
const SystemInfo = Authentication.lookup('SystemInfo');
const Os = Authentication.lookup('Os');
const CpuFamily = Authentication.lookup('CpuFamily');
const APWelcome = Authentication.lookup('APWelcome');
const AuthFailure = Authentication.lookup('AuthFailure');

function getAccesPoints() {
    return new Promise(function(resolve, reject) {
    	request('https://apresolve.spotify.com', { json: true }, (err, res, body) => {
            if (err) return reject(err);
            try {
                resolve(body.ap_list);
            } catch(e) {
                reject(e);
            }
        });
    });
}

function getClientHello(keys) {
    let nonce = Buffer.alloc(16);
    crypto.randomFillSync(nonce);

    return ClientHello.encode(ClientHello.create({
		buildInfo: BuildInfo.create({
	        product: Product.values.PRODUCT_PARTNER,
	        platform: Platform.values.PLATFORM_LINUX_X86,
	        version: 0x10800000000
	    }),
		cryptosuitesSupported: [Cryptosuite.values.CRYPTO_SUITE_SHANNON],
		loginCryptoHello: LoginCryptoHelloUnion.create({
	    	diffieHellman: LoginCryptoHelloUnion.create({
	        	gc: keys.getPublicKey(),
	            serverKeysKnown: 1
	        })
	    }),
		clientNonce: nonce,
		padding: Buffer.from([30])
    })).finish();
}

function intToBuffer(val) {
	let writeBuffer = Buffer.alloc(1);
	writeBuffer[0] = val;
	return writeBuffer;
}

function getLogin(server, username, password) {
	let deviceId = uuidv4();

	return new Promise(function(resolve, reject) {
		let keys = new Keys();
		let acc = new Accumulator();
		
		let hello = getClientHello(keys);
		let incomingMethod = 'welcome';
		let options = { port: server.split(':', 2)[1], host: server.split(':', 2)[0] };
		let socket = net.Socket(options);
		socket.setTimeout(5000);
		let timeoutLogin;

		let failMessage = function(data) {
			clearTimeout(timeoutLogin);
			
			let length = data.readInt32BE(0);

	        let b = data.slice(4, length);

	        let decodedMessage = APResponseMessage.decode(b);
	
	        let error;
	        switch(decodedMessage.loginFailed.errorCode) {
	        	case 0:
	        		error = 'ProtocolError';
	        		break;
	        	case 2:
	        		error = 'TryAnotherAP';
	        		break;
	        	case 5:
	        		error = 'BadConnectionId';
	        		break;
	        	case 9:
	        		error = 'TravelRestriction';
	        		break;
	        	case 11:
	        		error = 'PremiumAccountRequired';
	        		break;
	        	case 12:
	        		error = 'BadCredentials';
	        		break;
	        	case 13:
	        		error = 'CouldNotValidateCredentials';
	        		break;
	        	case 14:
	        		error = 'AccountExists';
	        		break;
	        	case 15:
	        		error = 'ExtraVerificationRequired';
	        		break;
	        	case 16:
	        		error = 'InvalidAppKey';
	        		break;
	        	case 17:
	        		error = 'ApplicationBanned';
	        		break;
	        	default:
	        		error = 'unkown error code:' + decodedMessage.loginFailed.errorCode;
	        }
	        reject(error);
	        socket.end();
		}
	
		let cipherPair;
		let continueLogin = function(data) {
	        // Init Shannon cipher
	        cipherPair = new Cipher(data.slice(0x14, 0x34), data.slice(0x34, 0x54));

	        let payload = {
	        	username: username,
	        	typ: AuthenticationType.values.AUTHENTICATION_USER_PASS,
	        	authData: Buffer.from(password)
	        };
	
	        let message = LoginCredentials.create(payload);
	
	        let clientResponseEncrypted = ClientResponseEncrypted.create({
		        loginCredentials: message,
		        systemInfo: SystemInfo.create({
		        	os: Os.values.OS_UNKNOWN,
		            cpuFamily: CpuFamily.values.CPU_UNKNOWN,
		            systemInformationString: 'librespot-java 0.1.3; Java 9.0.4; Windows 10',
		            deviceId: deviceId
		        }),
		        versionString: 'librespot-java 0.1.3',
	        });
	
	        incomingMethod = 'auth';
	        cipherPair.sendEncoded(socket, 0xab, ClientResponseEncrypted.encode(clientResponseEncrypted).finish());
		}
	
		let parseWelcomeMessage = function (data) {
			let length = data.readInt32BE(0);
			acc.writeInt(length);
	
	        let b = data.slice(4, length);
	        acc.write(b);

	        let decodedMessage = APResponseMessage.decode(b);
	        let sharedKey = keys.computeSharedKey(decodedMessage.challenge.loginCryptoChallenge.diffieHellman.gs);
	
	        let dataArray = Buffer.from([]);
	
	        let mac = crypto.createHmac('sha1', sharedKey);
	        for (let i = 1; i < 6; i++) {
	            mac.update(acc.array());
	            mac.update(intToBuffer(i));
	
	            dataArray = Buffer.concat([dataArray, mac.digest()]);
	
	            mac = crypto.createHmac('sha1', sharedKey);
	        }
	
	        mac = crypto.createHmac('sha1', dataArray.slice(0, 20));
	        mac.update(acc.array());
	        
	        let challenge = mac.digest();
	
	        let clientResponsePlaintext = ClientResponsePlaintext.create({
	            loginCryptoResponse: LoginCryptoResponseUnion.create({diffieHellman: LoginCryptoDiffieHellmanResponse.create({hmac: challenge})}),
	            powResponse: PoWResponseUnion.create({}),
	            cryptoResponse: CryptoResponseUnion.create({})        	
	        });
	
	        let clientResponsePlaintextBytes =  ClientResponsePlaintext.encode(clientResponsePlaintext).finish();
			let buf = Buffer.alloc(4);
			buf.writeUInt32BE(4 + clientResponsePlaintextBytes.length, 0);
			socket.write(buf);
	
			incomingMethod = 'fail';
			socket.write(clientResponsePlaintextBytes);
	
			timeoutLogin = setTimeout(function () {
				incomingMethod = 'read';
				continueLogin(dataArray);
			}, 1000);
		};
	
		let parsePacket = function(packet) {
			let decodedMessage;

			switch(packet.cmd) {
			case 0x02:
				// SecretBlock
				break;
			case 0x04:
				// Ping
				break;
			case 0x08:
				// StreamChunk
				break;
			case 0x09:
				// StreamChunkRes
				break;
			case 0x0a:
				// ChannelError
				break;
			case 0x0b:
				// ChannelAbort
				break;
			case 0x0c:
				// RequestKey
				break;
			case 0x0d:
				// AesKey
				break;
			case 0x0e:
				// AesKeyError
				break;
			case 0x19:
				// Image
				break;
			case 0x1b:
				// CountryCode
				break;
			case 0x49:
				// Pong
				break;
			case 0x4a:
				// PongAck
				break;
			case 0x4b:
				// Pause
				break;
			case 0x50:
				// ProductInfo
				break;
			case 0x69:
				// LegacyWelcome
				break;
			case 0x76:
				// LicenseVersion
				break;
			case 0xab:
				// Login
				break;
			case 0xac:
				// APWelcome

		        decodedMessage = APWelcome.decode(packet.payloadBytes);

		        resolve({
		        	username: decodedMessage.canonicalUsername,
		        	authType: decodedMessage.reusableAuthCredentialsType,
		        	authData: decodedMessage.reusableAuthCredentials
		        });
		        
		        socket.end();
				break;
			case 0xad:
				// AuthFailure
		    	
		        decodedMessage = AuthFailure.decode(packet.payloadBytes);

				reject(decodedMessage);

				socket.end();
				break;
			case 0xb2:
				// MercuryReq
				break;
			case 0xb3:
				// MercurySub
				break;
			case 0xb4:
				// MercuryUnsub
				break;
			case 0xb5:
				// MercurySubEvent
				break;
			case 0x1f:
				// UnknownData_AllZeros
				break;
			case 0x4f:
				// Unknown_0x4f
				break;
			case 0x0f:
				// Unknown_0x0f
				break;
			case 0x10:
				// Unknown_0x10
				break;
	        default:
	        	// unkown
			}
		}
		
		let parseData = function(data) {
			if(incomingMethod == 'fail') {
				failMessage(data);
			} else if(incomingMethod == 'welcome') {
				parseWelcomeMessage(data);
			} else if(incomingMethod == 'auth') {
				// read data via stream
	
				let d = Buffer.concat([lastBuf, data]);
				let r = cipherPair.receiveEncoded(d);
	
				if(!r.complete) {
					lastBuf = d;
					return;
				} else {
					parsePacket(r);
					lastBuf = r.next;
				}
	
				if(lastBuf.length > 0) {
					parseData(Buffer.from([]));
				}
			}
		};
	
		let lastBuf = Buffer.from([]);
		socket.on('data', data => {
			parseData(data);
		});
		socket.on('end', () => {
			reject('disconnected from server');
		});
		socket.on('error', (err) => {
			reject('server error: ' + JSON.stringify(err));
		});
		socket.on('timeout', () => {
		    reject('socket timeout');
		    socket.end();
		});
		socket.on('connect', () => {
			setTimeout(function () {
				let length = 2 + 4 + hello.length;

				acc.writeByte(0);
				acc.writeByte(4);
				acc.writeInt(length);
				acc.write(hello);

				socket.write(acc.array());
			}, 1000);
		});
		socket.connect(options);
	});
}

module.exports = function(username, password, callback) {
	return new Promise(function(resolve, reject) {
		return getAccesPoints().then(function(items) {
			let p = Promise.resolve().then(function () {
				return getLogin(items[0], username, password);
			})

			for(let i = 1; i < items.length; i++) {
				p = p.catch(function(e) {
					return getLogin(items[i], username, password);
				});
			}

			return p;
		}).then(function(val) {
			resolve(val);
			if(callback) {
				callback(null, val);
			}
		}).catch(function(e) {
			reject(e);
			if(callback) {	
				callback(e, null);
			}
		});
	});
}
