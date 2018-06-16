var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var uuid = require('node-uuid');
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
var constants = require('./constants');
var pool = mysql.createPool(constants.MYSQL_OPTIONS);
var common = require('./common');
var hashedPassword = require('password-hash');
const async = require('async');
const generator = require('generate-password');
function auth_code(req, web3, appId, params_encrypt, res) {
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function checkWeb3(connection, callback) {
			if (web3.isConnected())
			{
				callback(null, connection);
			}
			else
			{
				callback("auth-code Error Occured", connection, constants.ERR_CONSTANTS.web3_err);
			}
		},
		function decryptParams(connection, callback) {
			var aesKey;
			common.get_aeskey(connection, appId, function(result) {
				aesKey = result.aesKey;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr)
					{
						var mailAddr = params.mailaddr;
						var lang = params.region ? params.region: 'en';
						callback(null, connection, mailAddr, lang, aesKey);
					}
					else
					{
						callback("auth-code Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-code Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function isExist(connection, mailAddr, lang, aesKey, callback) 
		{
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						callback("auth-code Error Occured", connection, constants.ERR_CONSTANTS.alreadyreg_err, aesKey);
					}
					else
					{
						callback(null, connection, mailAddr, lang, aesKey);
					}
				}
			});
		},
		function regUserTemp(connection, mailAddr, lang, aesKey, callback)
		{
			sql = 'SELECT * FROM users_temp WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						sql = 'UPDATE users_temp SET verify_code = ? WHERE mail_addr = ?';
					}
					else
					{
						sql = 'INSERT INTO users_temp (verify_code, mail_addr) VALUES (?, ?)';
					}
					var verifyCode = common.generate_verifycode(6);
					connection.query(sql, [verifyCode, mailAddr], function(err, rows) {
						if (err)
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							callback(null, connection, mailAddr, lang, verifyCode, aesKey);
						}
					});
				}
			});
		},
		function postMail(connection, mailAddr, lang, verifyCode, aesKey, callback)
		{
			var mailOptions = {
				to: mailAddr,//'rks@jxgi.com'
				subject: 'Account Verification',
				data: {  // data to view template, you can access as - user.name
				  name: mailAddr,
				  code: verifyCode
				}
			};
			//var jadeMail = lang == 'en' ? 'registeremail' : 'registeremailjp';
			var jadeMail = 'registeremail';
			req.app.mailer.send(jadeMail, mailOptions, function(err,message) {
				if (err) {
					 callback(err, connection, constants.ERR_CONSTANTS.mail_err, aesKey);
				}
				else
				{
					callback(null, connection, constants.ERR_CONSTANTS_success, aesKey);
				}
			});
		}
	],
		function(err, connection, code, aesKey) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
				console.log("code : " + code + ", err : " + err);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_verify(web3, jwt, appId, params_encrypt, res){
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function checkWeb3(connection, callback) {
			if (web3.isConnected())
			{
				callback(null, connection);
			}
			else
			{
				callback("auth-verify Error Occured", connection, constants.ERR_CONSTANTS.web3_err);
			}
		},
		function decryptParams(connection, callback) {
			var aesKey;
			common.get_aeskey(connection, appId, function(result) {
				aesKey = result.aesKey;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.verificationcode)
					{
						var mailAddr = params.mailaddr;
						var verifyCode = params.verificationcode;
						callback(null, connection, mailAddr, verifyCode, aesKey);
					}
					else
					{
						callback("auth-verify Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-verify Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function isExistUsers(connection, mailAddr, verifyCode, aesKey, callback)
		{
			var isExistUsersTb = false;
			var userId = 0;
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						callback('auth-verify Error Occured', connection, constants.ERR_CONSTANTS.alreadyreg_err);
					}
					else
					{
						callback(null, connection, mailAddr, userId, verifyCode, aesKey);
					}
				}
			});
		},
		function isExistUserTemp(connection, mailAddr, userId, verifyCode, aesKey, callback)
		{
			sql = 'SELECT * FROM users_temp WHERE mail_addr = ? AND verify_code = ?';
			connection.query(sql, [mailAddr, verifyCode], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						var userTempId = rows[0].id;
						sql = 'DELETE FROM users_temp WHERE id = ?';
						connection.query(sql, userTempId, function(err, rows) {
							if (err)
							{
								callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
							}
							else
							{
								callback(null, connection, mailAddr, userId, verifyCode, aesKey);	
							}
						});
					}
					else
					{
						callback('auth-verify Error Occured', connection, constants.ERR_CONSTANTS.userreq_err, aesKey);
					}
				}
			});
		},
		function insertUsers(connection, mailAddr, userId, verifyCode, aesKey, callback)
		{
			var userIdentify = 0;
			sql = 'INSERT INTO users (mail_addr, verify_code) VALUES (?, ?)';
			connection.query(sql, [mailAddr, verifyCode], function(err, rows){
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					userIdentify = rows.insertId;
					callback(null, connection, userIdentify, aesKey);
				}
			});

		},
		function setUserId(connection, userIdentify, aesKey, callback)
		{
			sql = 'UPDATE sessions SET user_id = ? WHERE aes_key = ?';
			connection.query(sql, [userIdentify, aesKey], function(err, rows){
				if (err)
				{
					callback("auth-verify Error Occured", connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					callback(null, connection, aesKey);
				}
			});
		},
		function updateToken(connection, aesKey, callback)
		{
			var sessToken = jwt.sign({aesKey:aesKey}, "secret", { expiresIn: 60*20 });
			common.update_token(connection, appId, sessToken, function(result) {
				if (result)
				{
					callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, sessToken);
				}
				else
				{
					callback("auth-verify Error Occured", connection, constants.ERR_CONSTANTS.token_err, aesKey);
				}
			});
		},
	],
		function(err, connection, code, aesKey, sessToken) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code, "token": null};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "token": sessToken};
			}
			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_password(web3, jwt, appId, params_encrypt, res) {
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.password && params.token)
					{
						var mailAddr = params.mailaddr;
						var encryptPassword = params.password;
						var encryptedOldPassword = params.oldpassword;
						var sessToken = params.token;
						callback(null, connection, mailAddr, encryptPassword, encryptedOldPassword, sessToken, aesKey);
					}
					else
					{
						callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function decryptPassword(connection, mailAddr, encryptPassword, encryptedOldPassword, sessToken, aesKey, callback) {
			sql = 'SELECT * FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						var password = common.decrypt_rsa(encryptPassword, rows[0].priv_key);
						if (password)
						{
							var oldPassword = common.decrypt_rsa(encryptedOldPassword, rows[0].priv_key);
							callback(null, connection, mailAddr, password, oldPassword, sessToken, aesKey);
						}
						else
						{
							callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.key_err);
						}
					}
					else
					{
						callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
					}
				}
			});
		},
		function createWallet(connection, mailAddr, password, oldPassword, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					sql = 'SELECT * FROM users WHERE mail_addr = ?';
					connection.query(sql, mailAddr, function(err, rows) {
						if (err)
						{
							callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							if (rows.length > 0)
							{
								var currentWalletPassword = rows[0].wallet_password;
								var walletAdress = rows[0].wallet_addr;
								var walletPassword;
								if (currentWalletPassword)
								{
									var oldKey = common.generate_hash(oldPassword);
									walletPassword =  common.decrypt_aes_wallet(currentWalletPassword, oldKey);
									var newKey = common.generate_hash(password);
									walletPassword = common.encrypt_aes(walletPassword, newKey);
									if (walletPassword)
									{
										callback(null, connection, mailAddr, password, walletAdress, walletPassword, aesKey);
									}
									else
									{
										callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.idpass_err, aesKey);
									}
									
								}
								else
								{
									var newWalletPassword = generator.generate({  
										length: 10,
										numbers: true,
										symbols : true
									});
									try
									{
										web3.personal.newAccount(newWalletPassword, function(error, result) {
											if (error)
											{
												callback(error, connection, constants.ERR_CONSTANTS.wallet_err, aesKey);
											}
											else
											{
												var key = common.generate_hash(password);
												walletPassword = common.encrypt_aes(newWalletPassword, key);
												walletAdress = result;
												callback(null, connection, mailAddr, password, walletAdress, walletPassword, aesKey);
											}
										});										
									}
									catch (exception)
									{
										callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.wallet_err, aesKey);
									}
									
								}
							}
							else
							{
								callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.noreguser_err);
							}
						}
					});
				}
				else
				{
					callback("auth-password Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function regPassword(connection, mailAddr, password, walletAdress, walletPassword, aesKey, callback) {
			sql = 'UPDATE users SET password = ?, wallet_addr = ?, wallet_password = ? WHERE mail_addr = ?';
			connection.query(sql, [hashedPassword.generate(password), walletAdress, walletPassword, mailAddr], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
				}
			});
		},
	],
		function(err, connection, code, aesKey) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_forgot(appId, params_encrypt, res) {
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr)
					{
						var mailAddr = params.mailaddr;
						callback(null, connection, mailAddr, aesKey);
					}
					else
					{
						callback("auth-forgot Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-forgot Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function isRegUser(connection, mailAddr, aesKey, callback) {
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
					}
					else
					{
						callback("auth-forgot Error Occured", connection, constants.ERR_CONSTANTS.unregmailaddr_err, aesKey);
					}
				}
			});
		},
	],
		function(err, connection, code, aesKey) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function check_password(jwt, appId, params_encrypt, res) {
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.password && params.token)
					{
						var mailAddr = params.mailaddr;
						var encryptPassword = params.password;
						var sessToken = params.token;
						callback(null, connection, mailAddr, encryptPassword, sessToken, aesKey);
					}
					else
					{
						callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function decryptPassword(connection, mailAddr, encryptPassword, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					sql = 'SELECT * FROM app_informs WHERE app_id = ?';
					connection.query(sql, appId, function(err, rows) {
						if (err)
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							if (rows.length > 0)
							{
								var password = common.decrypt_rsa(encryptPassword, rows[0].priv_key);
								callback(null, connection, mailAddr, password, aesKey);
							}
							else
							{
								callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
							}
						}
					});
				}
				else
				{
					callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function isValidUsers(connection, mailAddr, password, aesKey, callback)
		{
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						if (hashedPassword.verify(password, rows[0].password)) { //default sha1
							callback(null, connection, 0, aesKey);
						}
						else
						{
							callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.idpass_err, aesKey);
						}
					}
					else
					{
						callback("auth-checkpassword Error Occured", connection, constants.ERR_CONSTANTS.idpass_err, aesKey);
					}
				}
			});
		},
	],
		function(err, connection, code, aesKey) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_login(jwt, appId, params_encrypt, res) {
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.password)
					{
						var mailAddr = params.mailaddr;
						var encryptPassword = params.password;
						callback(null, connection, mailAddr, encryptPassword, aesKey);
					}
					else
					{
						callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function decryptPassword(connection, mailAddr, encryptPassword, aesKey, callback) {
			sql = 'SELECT * FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						var password = common.decrypt_rsa(encryptPassword, rows[0].priv_key);
						callback(null, connection, mailAddr, password, aesKey);
					}
					else
					{
						callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
					}
				}
			});
		},
		function isValidUsers(connection, mailAddr, password, aesKey, callback)
		{
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						if (hashedPassword.verify(password, rows[0].password)) { //default sha1
							var verifyCode = rows[0].verify_code;
							var userId = rows[0].id;
							callback(null, connection, userId, mailAddr, verifyCode, aesKey);
						}
						else
						{
							callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.idpass_err, aesKey);
						}
					}
					else
					{
						callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.idpass_err, aesKey);
					}
				}
			});
		},
		function setUserId(connection, userId, mailAddr, verifyCode, aesKey, callback)
		{
			sql = 'UPDATE sessions SET user_id = ? WHERE aes_key = ?';
			connection.query(sql, [userId, aesKey], function(err, rows){
				if (err)
				{
					callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					callback(null, connection, mailAddr, verifyCode, aesKey);
				}
			});
		},
		function updateToken(connection, maillAddr, verifyCode, aesKey, callback)
		{
			var sessToken = jwt.sign({aesKey:aesKey}, "secret", { expiresIn: 60*20 });
			common.update_token(connection, appId, sessToken, function(result) {
				if (result)
				{
					callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, sessToken);
				}
				else
				{
					callback("auth-login Error Occured", connection, constants.ERR_CONSTANTS.token_err, aesKey);
				}
			});
		},
	],
		function(err, connection, code, aesKey, sessToken) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code, "token": null};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "token": sessToken};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_logout(jwt, appId, params_encrypt, res) {
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.token)
					{
						var mailAddr = params.mailaddr;
						var sessToken = params.token;
						callback(null, connection, mailAddr, sessToken, aesKey);
					}
					else
					{
						callback("auth-logout Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-logout Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function updateToken(connection, mailAddr, sessToken, aesKey, callback)
		{
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					common.update_token(connection, appId, '', function(res) {
						if (res)
						{
							callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
						}
						else
						{
							callback("auth-logout Error Occured", connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
					});
				}
				else
				{
					callback("auth-logout Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
	],
		function(err, connection, code, aesKey) {
			var body;
			connection.release();
			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_backup(jwt, appId, params_encrypt, res) {
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.password && params.key && params.token)
					{
						var mailAddr = params.mailaddr;
						var encryptPassword = params.password;
						var sessToken = params.token;
						var hintKey = params.key;
						callback(null, connection, mailAddr, encryptPassword, sessToken, hintKey, aesKey);
					}
					else
					{
						callback("auth-backup Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-backup Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function decryptPassword(connection, mailAddr, encryptPassword, sessToken, hintKey, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					sql = 'SELECT * FROM app_informs WHERE app_id = ?';
					connection.query(sql, appId, function(err, rows) {
						if (err)
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							if (rows.length > 0)
							{
								var password = common.decrypt_rsa(encryptPassword, rows[0].priv_key);
								callback(null, connection, mailAddr, password, hintKey, aesKey);
							}
							else
							{
								callback("auth-backup Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
							}
						}
					});
				}
				else
				{
					callback("auth-backup Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function backupPassword(connection, mailAddr, password, hintKey, aesKey, callback)
		{
			var backupPassword = common.encrypt_aes(password, hintKey);
			if (backupPassword)
			{
				sql = 'UPDATE users SET backup_password = ? WHERE mail_addr = ?';
				connection.query(sql, [backupPassword, mailAddr], function(err, rows){
					if (err)
					{
						callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
					}
					else
					{
						callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
					}
				});
			}
			else
			{
				callback("auth-backup Error Occured", connection, constants.ERR_CONSTANTS.backup_err, aesKey);
			}
		},
	],
		function(err, connection, code, aesKey) {
			var body;
			connection.release();
			if (err)
			{
				body = {"code": code};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
function auth_recovery(appId, params_encrypt, res) {
	var sql;
	async.waterfall([
		function getConn(callback) {
			pool.getConnection(function(err,conn) {
				var connection = conn;
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.connection_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function decryptParams(connection, callback) {
			common.get_aeskey(connection, appId, function(result) {
				var aesKey = result.aesKey;
				var userId = result.userId;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.key)
					{
						var mailAddr = params.mailaddr;
						var hintKey = params.key;
						callback(null, connection, mailAddr, hintKey, aesKey);
					}
					else
					{
						callback("auth-recover Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("auth-recover Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function decryptPassword(connection, mailAddr, hintKey, aesKey, callback) {
			sql = 'SELECT * FROM users WHERE mail_addr = ?';
			connection.query(sql, mailAddr, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						var encryptPassword = rows[0].backup_password;
						var password = common.decrypt_aes_wallet(encryptPassword, hintKey);

						if (password)
						{
							callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, mailAddr, password);
						}
						else
						{
							callback("auth-recover Error Occured", connection, constants.ERR_CONSTANTS.recover_err, aesKey);
						}
					}
					else
					{
						callback("auth-recover Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
					}
				}
			});
		},
	],
		function(err, connection, code, aesKey, mailAddr, password) {
			var body;
			connection.release();
			if (err)
			{
				body = {"code": code, "mailaddr": null, "password": null};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "mailaddr": mailAddr, "password": password};
			}

			if (aesKey)
			{
				var result = common.encrypt_aes(JSON.stringify(body),aesKey);
				res.setHeader('content-type', 'text/plain');
				res.send(result);
			}
		}
	);
}
router.post('/code', function(req, res, next) {
	var web3 = req.app.get('web3');
	var appId = req.query.appid;
	auth_code(req, web3, appId, req.body, res);
});
router.post('/forgot', function(req, res, next) {
	var appId = req.query.appid;
	auth_forgot(appId, req.body, res);
});
router.post('/verify', function(req, res, next) {
	var web3 = req.app.get('web3');
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	auth_verify(web3, jwt, appId, req.body, res);
});
router.post('/login', function(req, res, next) {
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	auth_login(jwt, appId, req.body, res);
});
router.post('/logout', function(req, res, next) {
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	auth_logout(jwt, appId, req.body, res);
});
router.post('/password', function(req, res, next) {
	var web3 = req.app.get('web3');
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	auth_password(web3, jwt, appId, req.body, res);
});
router.post('/checkpassword', function(req, res, next) {
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	check_password(jwt, appId, req.body, res);
});
router.post('/recovery', function(req, res, next) {
	var appId = req.query.appid;
	auth_recovery(appId, req.body, res)
});
router.post('/backup', function(req, res, next) {
	var jwt = req.app.get('jwt');
	var appId = req.query.appid;
	auth_backup(jwt, appId, req.body, res);
});
router.post('/genpass', function(req, res, next) {
	var password = generator.generate({
		length: 10,
		numbers: true,
		symbols : true
	});
	//res.setHeader('content-type', 'text/plain');
	res.json({"code":-1, "message":"FAIL","reason":2});
});

module.exports = router;
