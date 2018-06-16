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
function get_transactions(jwt, web3, appId, params_encrypt, res) {
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
					if (params && params.mailaddr && params.walletaddr && params.start && params.count && params.token)
					{
						var mailAddr = params.mailaddr;
						var walletAddr = params.walletaddr;
						var startNumber = params.start;
						var countNumber = params.count;
						var sessToken = params.token;
						callback(null, connection, mailAddr, walletAddr, startNumber, countNumber, sessToken, aesKey);
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
		function checkToken(connection, mailAddr, walletAddr, startNumber, countNumber, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					callback(null, connection, mailAddr, walletAddr, startNumber, countNumber, aesKey);
				}
				else
				{
					callback("transactions Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
		function getTransactions(connection, mailAddr, walletAddr, startNumber, countNumber, aesKey, callback) {
			var sql = 'SELECT * FROM txs WHERE from_addr = ? OR to_addr = ? LIMIT ?,?';
			connection.query(sql, [walletAddr, walletAddr, startNumber-1, countNumber], function(err, rows) {
				if (err)
				{
					callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
				}
				else
				{
					var result = [];
					var count = rows.length;
					var transaction;
					if (count > 0)
					{
						var index = 0;
						for (index = 0; index < count; index++ )
						{
							if (rows[index].from_addr == walletAddr)
							{
								transaction = {"from": rows[index].from_addr, "to": rows[index].to_addr, "value": rows[index].value, "time":rows[index].timestamp, "type":"send"};
							} else {
								transaction = {"from": rows[index].from_addr, "to": rows[index].to_addr, "value": rows[index].value, "time":rows[index].timestamp, "type":"receive"};
							}
							
							result.push(transaction);
						}
					}
					else
					{
							transaction = {"from": null, "to": null, "value": 0, "time": null, "type": 0};
							result.push(transaction);
					}
					callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, JSON.stringify(result), count);
				}
			});
		},
	],
		function(err, connection, code, aesKey, result, count) {
			var body;

			if (connection)
			{
				connection.release();
			}

			if (err)
			{
				body = {"code": code, "result": null, "count": 0};
				logger.info(err, code);
			}
			else
			{
				body = {"code": code, "result": result, "count":count};
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
	get_transactions(jwt, web3, appId, req.body, res);
});
module.exports = router;
