var express = require('express');
//var session = require('express-session');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var jws = require('express-jwt-session');
var mailer = require('express-mailer');
var Web3 = require('web3');
var web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:9000"));
var index = require('./routes/index');
var ssl = require('./routes/app');
var auth = require('./routes/auth');
var balance = require('./routes/balance');
var send = require('./routes/send');
var contacts = require('./routes/contacts');
var transactions = require('./routes/transactions');
var update = require('./routes/update');
var blockapi = require('./routes/blockapi');

var jwt = require("jsonwebtoken");
var app = express();

const https = require('https');
const fs = require('fs');
var credentials = {
	key: fs.readFileSync('./keys/server.key'),
	cert: fs.readFileSync('./keys/server.cer')
};
var PORT = 8000;
var HOST = '0.0.0.0';

server = https.createServer(credentials, app).listen(PORT, HOST);
console.log('HTTPS Server listening on %s:%s', HOST, PORT);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.set('jwt', jwt);
app.set('web3', web3);

mailer.extend(app, {		
	from: 'test19810913@163.com',
	host: 'smtp.163.com',//
	secureConnection: true,
	port: 587,
	transportMethod: 'SMTP',
	config: {
		auth: {
		  user: 'test19810913@163.com',
		  pass: 'wjdalgus'
		}
	}
});
//app.set('mailer', mailer);
// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
//app.use(bodyParser.json());
app.use(bodyParser.text());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//app.use(session({secret: 'ssshhhhh',saveUninitialized: true,resave: true}));

app.use('/', index);
app.use('/app', ssl);
app.use('/auth', auth);
app.use('/balance', balance);
app.use('/send', send);
app.use('/contacts', contacts);
app.use('/transactions', transactions);
app.use('/update', update);
app.use('/fxnow', blockapi);
// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
	res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;