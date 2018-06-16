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
function set_contacts(jwt, appId, params_encrypt, res) {
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
					if (params && params.mailaddr && params.walletaddr && params.contactname && params.token)
					{
						var mailAddr = params.mailaddr;
						var regWalletAddr = params.walletaddr;
						var regContactName = params.contactname;
						var sessToken = params.token;
						callback(null, connection, mailAddr, regWalletAddr, regContactName, sessToken, aesKey);
					}
					else
					{
						callback("contact-set Errors Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("contact-set Errors Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function addContact(connection, mailAddr, regWalletAddr, regContactName, sessToken, aesKey, callback) {
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
								var userId = rows[0].id;
								sql = 'INSERT INTO contacts (user_id, contact_name, wallet_addr) VALUES (?, ?, ?)';
								connection.query(sql, [userId, regContactName, regWalletAddr], function(err, rows) {
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
								callback("contact-set Errors Occured", connection, constants.ERR_CONSTANTS.noreguser_err);
							}
						}
					});
				}
				else
				{
					callback("contact-set Errors Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
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
function get_contacts(jwt, appId, params_encrypt, res){
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
						var getWalletAddr = params.walletaddr;
						var getContactName = params.contactname;
						var sessToken = params.token;
						callback(null, connection, mailAddr, userId, getWalletAddr, getContactName, sessToken, aesKey);
					}
					else
					{
						callback("contacts-get Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("contacts-get Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function getContacts(connection, mailAddr, userId, getWalletAddr, getContactName, sessToken, aesKey, callback)
		{
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					var sql = 'SELECT * FROM contacts WHERE user_id = ?';
					connection.query(sql, userId, function(err, rows) {
						if (err)
						{
							callback(err, connection, constants.ERR_CONSTANTS.query_err, aesKey);
						}
						else
						{
							var result = [];
							var count = rows.length;
							var realCount = 0;
							if (count > 0)
							{
								var index = 0;
								for (index = 0; index < count; index++ )
								{
									var contact;
									var isCorrect = false;
									if (getWalletAddr != '' && getContactName != '' )
									{
										if (rows[index].wallet_addr == getWalletAddr && rows[index].contact_name == getContactName)
										{
											isCorrect = true;
										}
									}
									else if (getWalletAddr != '')
									{
										if (rows[index].wallet_addr == getWalletAddr)
										{
											isCorrect = true;
										}
									}
									else if (getContactName != '')
									{
										if (rows[index].contact_name == getContactName)
										{
											isCorrect = true;
										}
									}
									else
									{
										isCorrect = true;
									}

									if (isCorrect)
									{
										realCount++;
										contact = {"contact_id":rows[index].id, "contact_name":rows[index].contact_name, "wallet_addr":rows[index].wallet_addr};
										result.push(contact);
									}
								}
							}
							callback(null, connection, constants.ERR_CONSTANTS.success, aesKey, JSON.stringify(result), realCount);
						}
					});
				}
				else
				{
					callback("contacts-get Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
				}
			});
		},
	],
		function(err, connection, code, aesKey, result, realCount) {
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
				body = {"code": code, "result": result, "count":realCount};
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

function modify_contacts(jwt, appId, params_encrypt, res){
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
				var userId = result.userId
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.contactid && params.newwalletaddr && params.newcontactname && params.token)
					{
						var mailAddr = params.mailaddr;
						var modContactId = params.contactid;
						var newWalletAddr = params.newwalletaddr;
						var newContactName = params.newcontactname;
						var sessToken = params.token;
						callback(null, connection, mailAddr, modContactId, newWalletAddr, newContactName, sessToken, aesKey);
					}
					else
					{
						callback("contact-modify Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("contact-modify Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function modifyContact(connection, mailAddr, modContactId, newWalletAddr, newContactName, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					var sql = 'UPDATE contacts SET contact_name = ?, wallet_addr = ? WHERE id = ?';
					connection.query(sql, [newContactName, newWalletAddr, modContactId], function(err, rows) {
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
					callback("contact-modify Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
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
function delete_contacts(jwt, appId, params_encrypt, res){
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
				var userId = result.userId
				if (aesKey)
				{
					var params = common.decrypt_aes(params_encrypt, aesKey);
					if (params && params.mailaddr && params.contactid && params.token)
					{
						var mailAddr = params.mailaddr;
						var delContactId = params.contactid;
						var sessToken = params.token;
						callback(null, connection, mailAddr, delContactId, sessToken, aesKey);
					}
					else
					{
						callback("contacts-delete Error Occured", connection, constants.ERR_CONSTANTS.params_err);
					}
				}
				else
				{
					callback("contacts-delete Error Occured", connection, constants.ERR_CONSTANTS.key_err);
				}
			});
		},
		function deleteContact(connection, mailAddr, delContactId, sessToken, aesKey, callback) {
			common.check_token(connection, mailAddr, sessToken, jwt, function(result) {
				if (result)
				{
					var sql = 'DELETE FROM contacts WHERE id = ?';
					connection.query(sql, delContactId, function(err, rows) {
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
					callback("contacts-delete Error Occured", connection, constants.ERR_CONSTANTS.tokenmismatch_err, aesKey);
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
router.post('/add', function(req, res, next) {
	jwt = req.app.get('jwt');
	var appId = req.query.appid;
	set_contacts(jwt, appId, req.body, res);
});
router.post('/get', function(req, res, next) {
	jwt = req.app.get('jwt');
	var appId = req.query.appid;
	get_contacts(jwt, appId, req.body, res);
});
router.post('/modify', function(req, res, next) {
	jwt = req.app.get('jwt');
	var appId = req.query.appid;
	modify_contacts(jwt, appId, req.body, res);
});
router.post('/delete', function(req, res, next) {
	jwt = req.app.get('jwt');
	var appId = req.query.appid;
	delete_contacts(jwt, appId, req.body, res);
});
module.exports = router;
