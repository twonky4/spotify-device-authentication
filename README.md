# spotify-device-authentication
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
	}
});
```

Using Promise:
```javascript
const credentialGenerator = require('spotify-device-authentication');

credentialGenerator('yourUserName', 'yourPassword')
	.then(function(val) {
		console.log(JSON.stringify(val));
	})
	.catch(function(err) {
		console.log(err);
	});
```