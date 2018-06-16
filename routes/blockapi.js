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


function send_raw_transaction(jwt, web3, hex, res) {
    async.waterfall([
            function sendPrice(callback) {
                 try
                 {
                     web3.eth.sendRawTransaction(hex, function (err, result) {
                         if (err)
                         {
                             callback(err, constants.ERR_CONSTANTS.sendrawtx_err, "0x");
                         }
                         else
                         {
                             callback(err, constants.ERR_CONSTANTS.sendrawtx_suc, result);
                         }
                     });
                 }
                 catch (exception) {
                     callback("send Error Occured", constants.ERR_CONSTANTS.sendrawtx_err, "0x");
                 }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}

function get_transaction_count(jwt, web3, address, tag, res) {
    async.waterfall([
            function eth_getTransactionCount(callback) {
                try
                {
                    web3.eth.getTransactionCount(address, tag, function (err, result) {
                        if (err)
                        {
                            callback(err, constants.ERR_CONSTANTS.gettxcount_err, -1);
                        }
                        else
                        {
                            callback(err, constants.ERR_CONSTANTS.gettxcount_suc, result);
                        }
                    });
                }
                catch (exception) {
                    callback("send Error Occured", constants.ERR_CONSTANTS.gettxcount_err, -1);
                }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code, "result": ret};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}

function get_balance_single(jwt, web3, address, res) {
    async.waterfall([
            function eth_balance_single(callback) {
                try
                {
                    web3.eth.getBalance(address, "latest", function (err, result) {
                        if (err)
                        {
                            callback(err, constants.ERR_CONSTANTS.getbalance_err, -1);
                        }
                        else
                        {
                            try {
                                var balance = web3.fromWei(result, "ether");
                                callback(err, constants.ERR_CONSTANTS.getbalance_suc, result);
                            }
                            catch (exception) {
                                callback("convert unit is error", constants.ERR_CONSTANTS.getbalance_err, -1);
                            }
                        }
                    });
                }
                catch (exception) {
                    callback("send Error Occured", constants.ERR_CONSTANTS.getbalance_err, -1);
                }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code, "result": ret};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}


function get_balance_multi(jwt, web3, address, res) {
    async.waterfall([
            function eth_balance_multi(callback) {
                try
                {
                    var address_array = address.split(",");
                    var result = {
                        results: []
                    };

                    for (var i = 0; i < address_array.length; i++) {
                        var addr = address_array[i];
                        var balance = web3.eth.getBalance(addr);
                        result.results.push({
                            account : addr,
                            balance : balance
                        });
                    }

                    callback("success", constants.ERR_CONSTANTS.getbalance_suc, result.results);
                }
                catch (exception) {
                    callback("send Error Occured", constants.ERR_CONSTANTS.getbalance_err, -1);
                }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code, "result": ret};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}

function get_estimateGas(jwt, web3, to, res) {
    async.waterfall([
            function eth_estimateGas(callback) {
                try
                {
                    var param = {from : to};
                    web3.eth.estimateGas(param, function (err, result) {
                        if (err)
                        {
                            callback(err, constants.ERR_CONSTANTS.getestimategas_err, -1);
                        }
                        else
                        {
                            callback(err, constants.ERR_CONSTANTS.getestimategas_suc, result);
                        }
                    });
                }
                catch (exception) {
                    callback("send Error Occured", constants.ERR_CONSTANTS.getbalance_err, -1);
                }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code, "result": ret};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}


function get_txlist(jwt, web3, address, startblock, endblock, res) {
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
            function getTransactions(connection, callback) {
                var sql = 'SELECT * FROM txs WHERE from_addr = ? OR to_addr = ?';
                connection.query(sql, [address, address], function(err, rows) {
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
                                if (rows[index].from_addr == address)
                                {
                                    transaction = {
                                        from: rows[index].from_addr,
                                        to: rows[index].to_addr,
                                        value: new web3.BigNumber(rows[index].value, 10),
                                        timeStamp: rows[index].timestamp,
                                        type: "send",
                                        nonce: rows[index].nonce,
                                        hash: rows[index].hash,
                                        blockNumber: rows[index].block_number,
                                        gasUsed: rows[index].acf_used,
                                        gasPrice: rows[index].acf_price};
                                } else {
                                    transaction = {
                                        from: rows[index].from_addr,
                                        to: rows[index].to_addr,
                                        value: new web3.BigNumber(rows[index].value, 10),
                                        timeStamp: rows[index].timestamp,
                                        type: "receive",
                                        nonce: rows[index].nonce,
                                        hash: rows[index].hash,
                                        blockNumber: rows[index].block_number,
                                        gasUsed: rows[index].acf_used,
                                        gasPrice: rows[index].acf_price};
                                }

                                result.push(transaction);
                            }
                        }
                        /*
                        else
                        {
                            transaction = {
                                from: null,
                                to: null,
                                value: 0,
                                timeStamp: null,
                                type: 0,
                                nonce: 0,
                                hash: null,
                                blockNumber: 0,
                                gasUsed: 0,
                                gasPrice: 0};
                            result.push(transaction);
                        }*/
                        callback(null, connection, constants.ERR_CONSTANTS.success, result, count);
                    }
                });
            },
        ],
        function(err, connection, code, result, count) {
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

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);
        }
    );
}

function get_blockNumber(jwt, web3, res) {
    async.waterfall([
            function eth_blockNumber(callback) {
                try
                {
                    var blockNumber = web3.eth.blockNumber;
                    callback(null, constants.ERR_CONSTANTS.getblocknumber_suc, blockNumber);
                }
                catch (exception) {
                    callback("send Error Occured", constants.ERR_CONSTANTS.getblocknumber_err, -1);
                }
            },
        ],
        function(err, code, ret) {
            var body;

            if (err)
            {
                body = {"code": code, "result": ret};
                logger.info(err, code);
            }
            else
            {
                body = {"code": code, "result": ret};
            }

            var result = JSON.stringify(body);
            res.setHeader('content-type', 'text/plain');
            res.send(result);

        }
    );
}

router.post('/api', function(req, res, next) {
    jwt = req.app.get('jwt');
    web3 = req.app.get('web3');
    var appId = req.query.appid;
    send_amount(jwt, web3, appId, req.body, res);
});

router.get('/api', function(req, res, next) {
    jwt = req.app.get('jwt');
    web3 = req.app.get('web3');
    var action = req.query.action;
    var apikey = req.query.apikey;

    if (action == "eth_sendRawTransaction" && apikey == constants.APP_KEY) {
        var hex = req.query.hex;
        send_raw_transaction(jwt, web3, hex, res);
    }

    else if (action == "eth_getTransactionCount" && apikey == constants.APP_KEY) {
        var address = req.query.address;
        var tag = req.query.tag;
        get_transaction_count(jwt, web3, address, tag, res);
    }

    else if (action == "balance" && apikey == constants.APP_KEY) {
        var address = req.query.address;
        get_balance_single(jwt, web3, address, res);
    }

    else if (action == "balancemulti" && apikey == constants.APP_KEY) {
        var address = req.query.address;
        get_balance_multi(jwt, web3, address, res);
    }

    else if (action == "eth_estimateGas" && apikey == constants.APP_KEY) {
        var toaddress = req.query.to;
        get_estimateGas(jwt, web3, toaddress, res);
    }

    else if (action == "txlistinternal" && apikey == constants.APP_KEY) {

    }

    else if (action == "txlist" && apikey == constants.APP_KEY) {
        var address = req.query.address;
        var startblock = req.query.startblock;
        var endblock = req.query.endblock;

        get_txlist(jwt, web3, address, startblock, endblock, res)
    }

    else if (action == "eth_blockNumber" && apikey == constants.APP_KEY) {
        get_blockNumber(jwt, web3, res);
    }
});

module.exports = router;
