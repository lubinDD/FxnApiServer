var express = require('express');
var router = express.Router();
var mysql = require('mysql');
//var hashedPassword = require('password-hash');
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
const constants = require('./constants');
const async = require('async');
const common = require('./common');
var pool = mysql.createPool(constants.MYSQL_OPTIONS);
function send_amount(jwt, web3, appId, params_encrypt, res) {
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
					if (params && params.mailaddr && params.password && params.addrsource && params.addrtarget && params.value && params.token)
					{
						var mailAddr = params.mailaddr;
						var encryptPassword = params.password;
						var addrSource = params.addrsource;
						var addrTarget = params.addrtarget;
						var fee = params.fee;
						var sendValue = params.value;
						var sessToken = params.token;
						callback(null, connection, mailAddr, encryptPassword, addrSource, addrTarget, sendValue, fee, sessToken, aesKey);
					}
					else
					{
						callback("send Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("send Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function checkToken(connection, mailAddr, encryptPassword, addrSource, addrTarget, sendValue, fee, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					callback(null, connection, mailAddr, encryptPassword, addrSource, addrTarget, sendValue, fee, aesKey);
				}
				else
				{
					callback("send Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function getUserPassword(connection, mailAddr, encryptPassword, addrSource, addrTarget, sendValue, fee, aesKey, callback) {
			var sql = 'SELECT *  FROM app_informs WHERE app_id = ?';
			connection.query(sql, appId, function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					var privKey = rows[0].priv_key;
					var userPassword = common.decrypt_rsa(encryptPassword, privKey);
					if (userPassword)
					{
						callback(null, connection, mailAddr, userPassword, addrSource, addrTarget, sendValue, fee, aesKey);
					}
					else
					{
						callback("send Error Occured", connection, constants.ERR_CONSTANTS.decryptkey_err, aesKey);
					}
				}
			});
		},
		function sendPrice(connection, mailAddr, userPassword, addrSource, addrTarget, sendValue, fee, aesKey, callback) {
			sql = 'SELECT * FROM users WHERE mail_addr = ? AND wallet_addr = ?';
			connection.query(sql, [mailAddr, addrSource], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					if (rows.length > 0)
					{
						var hashPassword = common.generate_hash(userPassword);
						var encryptWalletPassword = rows[0].wallet_password;
						walletPassword = common.decrypt_aes_wallet(encryptWalletPassword, hashPassword);
						try
						{
							web3.personal.unlockAccount(addrSource, walletPassword, function(err, result){
								if (err)
								{
									callback(err, connection, constants.ERR_CONSTANTS.unlockwallet_err, aesKey);
								}
								else
								{
									try
									{
										var gasPrice = fee * 10000000000;
										web3.eth.sendTransaction({from: addrSource, to: addrTarget, value:web3.toWei(sendValue), gasPrice: gasPrice}, function(err, result) {
											if (err)
											{
												callback(err, connection, constants.ERR_CONSTANTS.lowbalance_err, aesKey);
											}
											else
											{
												callback(null, connection, constants.ERR_CONSTANTS.success, aesKey);
											}
										});										
									}
									catch (exception)
									{
										callback("send Error Occured", connection, constants.ERR_CONSTANTS.unlockwallet_err, aesKey);				
									}
								}
							});
						}
						catch (exception)
						{
							callback("send Error Occured", connection, constants.ERR_CONSTANTS.invalidapass_err, aesKey);
						}
					}
					else
					{
						callback("send Error Occured", connection, constants.ERR_CONSTANTS.noreguser_err);
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

router.post('/', function(req, res, next) {
	jwt = req.app.get('jwt');
	web3 = req.app.get('web3');
	var appId = req.query.appid;
	send_amount(jwt, web3, appId, req.body, res);
});

module.exports = router;
