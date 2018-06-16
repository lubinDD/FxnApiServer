var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
var constants = require('./constants');
var pool = mysql.createPool(constants.MYSQL_OPTIONS);
const async = require('async');
const common = require('./common');
function get_balance(jwt, web3, appId, params_encrypt, res) {
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
					if (params && params.mailaddr && params.token)
					{
						var mailAddr = params.mailaddr;
						var sessToken = params.token;
						callback(null, connection, mailAddr, sessToken, aesKey);
					}
					else
					{
						callback("balance Error Occued", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("balance Error Occued", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function getAddressAndBalance(connection, mailAddr, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					var sql = 'SELECT * FROM users WHERE mail_addr = ?';
					connection.query(sql, mailAddr, function(err, rows) {
						if (err) 
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							if (rows.length > 0)
							{
								try
								{
									var walletAddr = rows[0].wallet_addr;
									var balance = web3.fromWei(web3.eth.getBalance(walletAddr));
									balance = Math.round(balance * 100) / 100;
									callback(null, connection, 0, aesKey, balance, walletAddr);
								}
								catch (exception)
								{
									callback("balance Error Occued", connection, constants.ERR_CONSTANTS.query_err, aesKey);
								}

							}
							else
							{
								callback("balance Error Occued", connection, constants.ERR_CONSTANTS.noreguser_err);
							}
						}
					});
				}
				else
				{
					callback("balance Error Occued", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		}
	],
		function(err, connection, code, aesKey, balance, walletAddr) {
			var body;
			if (connection)
			{
				connection.release();
			}

			if (err)
			{	
				body = {"code": code, "walletaddr": null, "balance":-1};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "walletaddr": walletAddr, "balance": balance};
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
function test_balance(web3, res) {
	console.log("getBalance");
	var balance = web3.eth.getBalance("0x6941e1c672ee925c166007e3bc51b3ad44a8001f");
	console.log("balance =", balance);
	body = {"balance": balance};
	res.send(body);
}
router.post('/', function(req, res, next) {
	jwt = req.app.get('jwt');
	web3 = req.app.get('web3');
	var appId = req.query.appid;
	get_balance(jwt, web3, appId, req.body, res);
});
router.get('/testBalance', function(req, res, next) {
	var web3 = req.app.get('web3');
	test_balance(web3, res);
});

module.exports = router;
