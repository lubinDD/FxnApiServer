var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var hashedPassword = require('password-hash');
var log4js = require('log4js');
log4js.configure('log-config.json');
var logger = log4js.getLogger('logging');
var pool = mysql.createPool({
	connectionLimit : 100,
	host	: 'localhost',
	user	: 'root',
	password: '',
	database: 'asec',
	debug	: false
});

function profile_get(req, mailaddr, token, res) {
	pool.getConnection(function(err,connection) {
		if (err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			logger.info('Error connecting database ... nn');
			return;
		}
		var sql = 'SELECT * from users where mailaddr = ? AND token = ?';
		var query = connection.query(sql, [mailaddr, token], function(err, rows) {
			connection.release();
			if (!err) {
				if (rows.length > 0)
				{
					res.json({"code":1, "message":"OK", "reason":0, "profile":{"mailaddr":rows[0].mailaddr, "wallet_addr":rows[0].wallet_addr}});
				}
				else
				{
					res.json({"code":-1, "message":"FAIL","reason":2});
				}
			}
		});
		query.on('error', function(err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			logger.info('Error while performing Query!!!');
			return;
		});
	});
}

function profile_set(req, mailaddr, password, fullname, token, res) {
	pool.getConnection(function(err,connection) {
		if (err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			logger.info('Error connecting database ... nn');
			return;
		}
		var sql = 'SELECT * from users where mailaddr = ? AND token = ?';
		var query = connection.query(sql, [mailaddr, token], function(err, rows) {
			if (!err) {
				if (rows.length > 0)
				{
					sql = 'UPDATE users SET password = ?, fullname = ? WHERE mailaddr = ?';
					query = connection.query(sql, [hashedPassword.generate(password), fullname, mailaddr]);
					res.json({"code":1, "message":"OK", "reason":0});
				}
				else
				{
					res.json({"code":-1, "message":"FAIL","reason":2});
				}
			}
		});
		query.on('error', function(err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			logger.info('Error while performing Query!!!');
			return;
		});
	});
}

router.get('/get', function(req, res, next) {
	var mailaddr = req.query.mailaddr;
	var token = req.query.token;
	profile_get(req, mailaddr, token, res);
});

router.get('/set', function(req, res, next) {
	var mailaddr = req.query.mailaddr;
	var password = req.query.password;
	var fullname = req.query.fullname;
	var token = req.query.token;
	profile_set(req, mailaddr, password, fullname, token, res);
});

router.post('/get', function(req, res, next) {
	var mailaddr = req.body.mailaddr;
	var token = req.body.token;
	profile_get(req, mailaddr, token, res);
});

router.post('/set', function(req, res, next) {
	var mailaddr = req.body.mailaddr;
	var password = req.body.password;
	var fullname = req.body.fullname;
	var token = req.query.token;
	profile_set(req, mailaddr, password, fullname, token, res);
});

module.exports = router;
