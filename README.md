# spotify-device-authentication

[![NPM version](https://img.shields.io/npm/v/spotify-device-authentication.svg)](https://www.npmjs.com/package/spotify-device-authentication)
[![Downloads](https://img.shields.io/npm/dm/spotify-device-authentication.svg)](https://www.npmjs.com/package/spotify-device-authentication)

[![NPM](https://nodei.co/npm/spotify-device-authentication.png?downloads=true)](https://nodei.co/npm/spotify-device-authentication/)

To add a user to a spotify device you need stored credentials. To generate these `authBlob` from username and password you need to connect to the spotify device api.

## Example
Using callback:
```javascript
const credentialGenerator = require('spotify-device-authentication');

credentialGenerator('yourUserName', 'yourPassword', function(err, val) {
	if(err) {
		console.log(err);
	} else {
		console.log(JSON.stringify(val));
		// val is: {username: 'yourUserName', authType: 1, authData: Buffer}
	}
});
```

Using Promise:
```javascript
const credentialGenerator = require('spotify-device-authentication');

credentialGenerator('yourUserName', 'yourPassword')
	.then(function(val) {
		console.log(JSON.stringify(val));
		// val is: {username: 'yourUserName', authType: 1, authData: Buffer}
	})
	.catch(function(err) {
		console.log(err);
	});
```