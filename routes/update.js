var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
const constants = require('./constants');
const async = require('async');
const common = require('./common');
var pool = mysql.createPool(constants.MYSQL_OPTIONS);
function update_key(jwt, appId, params_encrypt, res) {
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
			var aesKey;
			common.get_aeskey(connection, appId, function(result) {
				aesKey = result.aesKey;
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.password && params.token)
					{
						var mailAddr = params.mailaddr;
						var userPassword = params.password;
						var sessToken = params.token;
						callback(null, connection, mailAddr, userPassword, sessToken, aesKey);
					}
					else
					{
						callback("transactions Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("transactions Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function checkToken(connection, mailAddr, userPassword, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					callback(null, connection, mailAddr, userPassword, aesKey);
				}
				else
				{
					callback("transactions Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function getNewEncryptedPassword(connection, mailAddr, userPassword, aesKey, callback) {
			sql = 'SELECT * FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					var currentPrivKey = rows[0].priv_key;
					var password = common.decrypt_rsa(userPassword, currentPrivKey);
					if (!password)
					{
						callback("transactions Error Occured", connection, constants.ERR_CONSTANTS.decryptkey_err, aesKey);
					}
					else
					{
						var keyPair = common.generate_key();
						var pubKey = keyPair.pubkey;
						var privKey = keyPair.privkey;
						var encryptedPassword = common.encrypt_rsa(password, pubKey);
						callback(null, connection, pubKey, privKey, encryptedPassword, aesKey);
					}
				}
			});
		},
		function updateKeyPair(connection, pubKey, privKey, encryptedPassword, aesKey, callback) {
			sql = 'UPDATE app_informs SET priv_key = ?, pub_key = ? WHERE app_id = ?';
			connection.query(sql, [privKey, pubKey, appId], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, pubKey, encryptedPassword);
				}
			});
		},
	],
		function(err, connection, code, aesKey, pubKey, encryptedPassword) {
			var body;

			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code, "pubkey": null, "password": 0};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "pubkey": pubKey, "password":encryptedPassword};
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

router.post('/', function(req, res, next) {
	jwt = req.app.get('jwt');
	var appId = req.query.appid;
	update_key(jwt, appId, req.body, res);
});
module.exports = router;
