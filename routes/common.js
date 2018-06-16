var constants = require('./constants');
const crypto = require("crypto");
const nodeRSA = require('node-rsa');
module.exports = {
	decode : function decodeBase64(body) {
		var decoded = new Buffer(body, 'base64').toString('utf8');
		return decoded;
	},
	encode : function encodeBase64(body) {
		var encoded = new Buffer(body, 'utf8').toString('base64');
		return encoded;
	},
	generate_key: function generate_RSAKeyPair() {
		try
		{
			var key = new nodeRSA({b: 2048});
			var privKey = key.exportKey("pkcs8-private");
			var pubKey = key.exportKey("pkcs8-public-pem");
			var result = {"pubkey":pubKey, "privkey":privKey};
			return result;
		}
		catch(exception)
		{
			return null;
		}
		
	},
	encrypt_rsa: function encryptRSA(plain_text, pub_key) {
		try
		{
			var key = new nodeRSA();
			key.importKey(pub_key,"pkcs8-public");
			var encrypted = key.encrypt(plain_text, 'base64');
			return encrypted;
		}
		catch(exception)
		{
			return null;
		}

	},
	decrypt_rsa: function decryptRSA(cipher_text, priv_key) {
		try
		{
			var key = new nodeRSA();
			key.importKey(priv_key,"pkcs8-private");
			var decrypted = key.decrypt(cipher_text, 'utf8');
			return decrypted;			
		}
		catch (exception)
		{
			return null;
		}
	},
	encrypt_aes: function encryptAES(plain_text, aes_key) {
		try
		{
			var KEY = aes_key;
			var encryptor;
			KEY = new Buffer(KEY, 'base64');
			var PASSWORD = new Buffer(32);
			KEY.copy(PASSWORD, 0, 0, 32);
			var IV = new Buffer(16);
			KEY.copy(IV, 0, 32, 48);

			encryptor = crypto.createCipheriv(constants.SYMMETRIC_ALGORITHM, PASSWORD, IV);
			encryptor.setAutoPadding(true);
			encryptdata  = encryptor.update(plain_text, 'utf8', 'base64');
			encryptdata += encryptor.final('base64');
			return encryptdata;
		}
		catch (exception)
		{
			return null;
		}
		
	},
	decrypt_aes: function decryptAES(cipher_text, aes_key) {
		try
		{
			var KEY = aes_key;
			KEY = new Buffer(KEY, 'base64');//.toString('utf8');
			var PASSWORD = new Buffer(32);
			KEY.copy(PASSWORD, 0, 0, 32);
			var IV = new Buffer(16);
			KEY.copy(IV, 0, 32, 48);

			decryptor = crypto.createDecipheriv(constants.SYMMETRIC_ALGORITHM, PASSWORD, IV);
			decryptor.setAutoPadding(true);
			decryptordata = decryptor.update(cipher_text, 'base64', 'utf8');
			decryptordata += decryptor.final('utf8');
			var json_parse = JSON.parse(decryptordata);
			return json_parse;			
		}
		catch (exception)
		{
			return null;
		}
	},
	decrypt_aes_wallet: function decryptAES_WalletKey(cipher_text, aes_key) {
		try
		{
			var KEY = aes_key;
			KEY = new Buffer(KEY, 'base64');//.toString('utf8');
			var PASSWORD = new Buffer(32);
			KEY.copy(PASSWORD, 0, 0, 32);
			var IV = new Buffer(16);
			KEY.copy(IV, 0, 32, 48);

			decryptor = crypto.createDecipheriv(constants.SYMMETRIC_ALGORITHM, PASSWORD, IV);
			decryptor.setAutoPadding(true);
			decryptordata = decryptor.update(cipher_text, 'base64', 'utf8');
			decryptordata += decryptor.final('utf8');
			return decryptordata;
		}
		catch (exception)
		{
			return null;
		}
	},
	generate_verifycode: function generate(count) {
		var _sym = '1234567890';
		var str = '';

		for(var i = 0; i < count; i++) {
			str += _sym[parseInt(Math.random() * (_sym.length))];
		}
		return str;
		/*base.getID(str, function(err, res) {
			if(!res.length) {
				k(str)                   // use the continuation
			} else generate(count, k)  // otherwise, recurse on generate
		});*/
	},
	generate_hash: function generate_sha384(base_value) {
		try
		{
			//console.log("base_value=",base_value);
			var key = new Buffer(base_value, 'utf8');
			var shasum = crypto.createHash('sha384');
			shasum.update(key);
			key = shasum.digest('base64');
			//console.log(key);
			return key;			
		}
		catch (exception)
		{
			//console.log(exception);
			return null;
		}
	},
	get_aeskey : function getAesKey(connection, appId, callback) {
		sql = 'SELECT * FROM app_informs WHERE app_id = ?';
		var query = connection.query(sql, appId, function(err, rows) {
			if (!err)
			{
				if (rows.length > 0)
				{
					var devId = rows[0].id;
					sql = 'SELECT * FROM sessions WHERE dev_id = ?';
					query = connection.query(sql, devId, function(err, rows) {
						if (!err)
						{
							if (rows.length > 0)
							{
								var aesKey = rows[0].aes_key;
								var result = {aesKey: aesKey, userId: rows[0].user_id};
								return callback(result);
							}
							else
							{
								return callback(null);
							}
						}
					});
				}
				else
				{
					return callback(null);
				}
			}
		});
		query.on('error', function(err) {
			return callback(null);
		});
	},
	update_token : function updateToken(connection, appId, sessToken, callback) {
		sql = 'SELECT * FROM app_informs WHERE app_id = ?';
		var query = connection.query(sql, appId, function(err, rows) {
			if (!err)
			{
				if (rows.length > 0)
				{
					var devId = rows[0].id;
					sql = 'UPDATE sessions SET token = ? WHERE dev_id = ?';
					query = connection.query(sql, [sessToken, devId], function(err, rows) {
						if (!err)
						{
							return callback(true);
						}
					});
				}
				else
				{
					return callback(false);
				}
			}
		});
		query.on('error', function(err) {
			return callback(false);
		});
	},
	check_owner : function checkKeyOwner(connection, mailAddr, userId, callback) {
		return callback(true);
		sql = 'SELECT * FROM users WHERE id = ?';
		var query = connection.query(sql, userId, function(err, rows) {
			if (!err)
			{
				if (rows.length > 0)
				{
					if (rows[0].mail_addr == mailAddr)
					{
						return callback(true);
					}
					else
					{
						return callback(false);
					}
				}
				else
				{
					return callback(false);
				}
			}
		});
		query.on('error', function(err) {
			return callback(false);
		});
	},
	check_token : function checkUserToken(connection, mailAddr, sessToken, jwtObject, callback) {
		jwtObject.verify(sessToken, "secret", function(err, decoded) {
			if (err)
			{
				return callback(false);
			}
			else
			{
				sql = 'SELECT * FROM users WHERE mail_addr = ?';
				var query = connection.query(sql, mailAddr, function(err, rows) {
					if (!err)
					{
						if (rows.length > 0)
						{
							var userId = rows[0].id;
							sql = 'SELECT * FROM sessions WHERE user_id = ? AND token = ?';
							query = connection.query(sql, [userId, sessToken], function(err, rows) {
								if (rows.length > 0)
								{
									return callback(true);
								}
								else
								{
									return callback(false);
								}
							});
						}
						else
						{
							return callback(false);
						}
					}
				});						
				query.on('error', function(err) {
					return callback(false);
				});
			}
		});
	}
}
