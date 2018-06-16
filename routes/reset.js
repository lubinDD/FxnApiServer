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
function reset_password(req, mailaddr, password, token, res) {
	pool.getConnection(function(err,connection) {
		if (err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			return;
		}
		var sql = 'SELECT * FROM users WHERE mailaddr = ? AND token = ?';
		var query = connection.query(sql, [mailaddr, token], function(err, rows) {
			if (!err) {
				if (rows.length > 0)
				{
						sql = 'UPDATE users SET password = ? WHERE mailaddr = ?';
						query = connection.query(sql, [hashedPassword.generate(password), mailaddr]);
						res.json({"code":1, "message":"OK","reason":0});
				}
				else
				{
					res.json({"code":-1, "message":"FAIL","reason":2});
				}
			}
		});
		connection.release();
		query.on('error', function(err) {
			res.json({"code":-1, "message":"FAIL", "reason":1});
			logger.info('Error while performing Query!!!');
			return;
		});
	});
}

router.get('/password', function(req, res, next) {
	var mailaddr = req.query.mailaddr;
	var password = req.query.password;
	var token = req.query.token;
	reset_password(req, mailaddr, password, token, res);
});

router.post('/password', function(req, res, next) {
	var mailaddr = req.body.mailaddr;
	var password = req.body.password;
	var token = req.body.token;
	reset_password(req, mailaddr, password, token, res);
});
module.exports = router;
