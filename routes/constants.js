var define = require('node-constants')(exports);

define("CONSOLELOG_FLAG", 1);

define("METHOD_NEWUSER", 0);
define("METHOD_UPDATEUSER", 1);
define("SYMMETRIC_ALGORITHM" , 'AES-256-CBC');
define("HMAC_ALGORITHM" , 'SHA384');
define("APP_KEY", '9WAY9EDA7UUUFC2GAPZ4EBANGEZ6ECVVSC');
define("TNX_METHOD", {
	send		: 1,
	receive		: 2
});
define("MYSQL_OPTIONS", {
	connectionLimit : 100,
	host	: 'localhost',
	user	: 'root',
	password: '',
	database: 'fxnow_db',
	debug	: false
});
define("ERR_CONSTANTS",{
	success				: 0,
	connection_err		: 1,
	query_err			: -1,
	devagent_err		: 2,
	params_err			: 3,
	reg_err				: 4,
	key_err				: 5,
	noreguser_err		: 6,
	web3_err			: 7,
	tokenmismatch_err	: 101,
	idpass_err			: 102,
	keypair_err			: 201,
	mail_err			: 301,
	alreadyreg_err		: 302,
	hintmismatch_err	: 303,
	userreq_err			: 401,
	wallet_err			: 402,
	token_err			: 403,
	unlockwallet_err	: 501,
	lowbalance_err		: 502,
	invalidaddr_err		: 503,
	decryptkey_err		: 601,
	backup_err			: 701,
	recover_err			: 702,
	unregmailaddr_err	: 703,

    sendrawtx_suc		: 800,
	sendrawtx_err		: 801,

	gettxcount_suc		: 810,
	gettxcount_err		: 811,

	getbalance_suc		: 820,
	getbalance_err		: 821,

	getestimategas_suc	: 830,
	getestimategas_err	: 831,

	getblocknumber_suc 	: 840,
	getblocknumber_err	: 841
});