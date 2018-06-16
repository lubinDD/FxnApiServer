var express = require('express');
const fs = require('fs');
const crypto = require("crypto");
const common = require('./common');
const mysql = require('mysql');
const async = require('async');
const constants = require('./constants');
var router = express.Router();
var pool = mysql.createPool(constants.MYSQL_OPTIONS);
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
function get_appId(req, res) {
	const id = crypto.randomBytes(16).toString("hex");
	const timestamp = new Date().getTime();
	var appId;
	appId = timestamp + '_' + id;
	var shasum = crypto.createHash('sha1');
	shasum.update(appId);
	appId = shasum.digest('hex');
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
		function isExist(connection, callback) {
			sql = 'SELECT * FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err);
				}
				else
				{
					callback(null, connection);
				}
			});
		},
		function insertPrivAndPubKey(connection, callback) {
			var keyPair = common.generate_key();
			if (keyPair != null)
			{
				var privKey = keyPair.privkey;
				var pubKey = keyPair.pubkey;
				sql = 'INSERT INTO app_informs (app_id, priv_key, pub_key) VALUES (?, ?, ?)';
				connection.query(sql, [appId, privKey, pubKey], function(err, rows) {
					if (err)
					{
						callback(err, connection, constants.ERR_CONSTANTS.query_err);
					}
					else
					{
						callback(null, connection, constants.ERR_CONSTANTS.success, pubKey);
					}
				});
			}
			else
			{			
				callback("app-get Error Occured", connection, constants.ERR_CONSTANTS.keypair_err);
			}
		},
	],
		function(err, connection, code, pubKey) {
			var result;
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code, "appid": null, "appkey": null};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "appid": appId, "appkey":pubKey};
			}
			result = common.encode(JSON.stringify(body));
			res.setHeader('content-type', 'text/plain');
			res.send(result);
		}
	);
}
function set_session(req, res, appId, params_encrypt) {
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
			sql = 'SELECT * FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err);
				}
				else
				{
					if (rows.length > 0)
					{
						var params_decrypt = common.decrypt_rsa(params_encrypt, rows[0].priv_key);
						params_decrypt = JSON.parse(params_decrypt);
						if (params_decrypt && params_decrypt.devagent)
						{
							if (rows[0].device_agent == null || rows[0].device_agent == params_decrypt.devagent)
							{
								var devId = rows[0].id;
								callback(null, connection, params_decrypt, devId);
							}
							else
							{
								callback("app-set Error Occured", connection, constants.ERR_CONSTANTS.devagent_err);
							}
						}
						else
						{
							callback("app-set Error Occured", connection, constants.ERR_CONSTANTS.params_err);
						}
					}
					else
					{
						callback("app-set Error Occured", connection, constants.ERR_CONSTANTS.reg_err);
					}
				}
			});
		},
		function regDevAgent(connection, params_decrypt, devId, callback) {
			sql = 'UPDATE app_informs SET device_agent = ? WHERE app_id = ?';
			connection.query(sql, [params_decrypt.devagent, appId], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err);
				}
				else
				{
					var aesKey = new Buffer(params_decrypt.sessionkey, 'hex');
					var shasum = crypto.createHash('sha384');
					shasum.update(aesKey);
					aesKey = shasum.digest('base64');
					callback(null, connection, devId, aesKey);
				}
			});
		},
		function regAesKey(connection, devId, aesKey, callback) {
			sql = 'SELECT * FROM sessions WHERE dev_id = ?'
			connection.query(sql, devId, function(err,rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err);
				}
				else
				{
					if (rows.length > 0)
					{
						sql = 'UPDATE sessions SET aes_key = ? WHERE dev_id = ?'; 
					}
					else
					{
						sql = 'INSERT INTO sessions (aes_key, dev_id) VALUES (?, ?)';
					}
					connection.query(sql, [aesKey, devId], function(err, rows) {
						if (err)
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err);
						}
						else
						{
							callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
						}
					});
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

function test_cipher(res, base) {
	/*var body = {"code": 1, "reason": 0};
	var cipher_test = common.encrypt_aes(JSON.stringify(body),'aaa');
	console.log("encrypt = ", cipher_test);
	cipher_test = common.decrypt_aes(cipher_test, 'aaa');
	console.log("decrypt = ", cipher_test);
	res.setHeader('content-type', 'text/plain');
	res.send(cipher_test);*/
	/*var key = new nodeRSA({b: 2048});
	var pubKey = key.exportKey("pkcs8-private");
	var privKey = key.exportKey("pkcs8-public-pem");
	
	var body = {"pubkey":pubKey, "privkey":privKey};

	result = common.encode(JSON.stringify(body));*/
	/*var hash = crypto.createHash('sha384')
			.update('12345678', 'utf8')
			.digest('base64');*/

	var key = new Buffer(base, 'utf8');
	var shasum = crypto.createHash('sha384');
	shasum.update(key);
	key = shasum.digest('base64');
	console.log(key);

	res.setHeader('content-type', 'text/plain');
	res.send(key);
}
router.get('/get', function(req, res, next) {
	get_appId(req, res);
});

router.post('/get', function(req, res, next) {
	get_appId(req, res);
});

router.post('/set', function(req, res, next) {
	var appId = req.query.appid;
	var params = req.body;
	set_session(req, res, appId, params);
});

router.get('/test', function(req, res, next) {
	var base= req.query.base;
	test_cipher(res, base);
});
module.exports = router;
