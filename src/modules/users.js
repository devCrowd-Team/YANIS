'use strict'

var Q = require('q');
var bunyan = require('bunyan');
var Datastore = require('nedb');
var packageConfig = require('../../package');
var usersDb = new Datastore({ filename: 'users.db', autoload: true });
var logging = bunyan.createLogger({name: packageConfig.name});

exports.GetHashedPasswordFor = function(userId){
	
	var d = Q.defer();
	
	usersDb.findOne({ userId : userId}, function(err, account){
		if(err){
			d.reject(err);
		}
		
		if(account){
			d.resolve(account.hashedPassword);
		} else {
			d.reject(new Error("Unknown userId"))
		}
	});
	
	return d.promise
};

exports.SetHashedPassword = function(req, res, next){
	
	var account = {
		userId : req.body.userId,
		hashedPassword : req.body.hashedPassword
	};
	
	logging.info("Set Account: " + account);
	
	usersDb.find({ userId : account.userId } , function(err, existingAccount){
		
		// No Account found ;)
		if(existingAccount.length == 0){
			
			usersDb.insert(account, function(err, newAccount){
				if(err == null){
					logging.info("Oh, a new Account");
					res.send(200);
				} else {
					logging.error(err);
					next(err);
				}
			});
		}
		// Or user exists :P 
		else {
			
			usersDb.update(existingAccount[0], account, function(err, changedCount){
				
				if(err == null){
					logging.info("existing Account changed");
					res.send(200);
				} else {
					logging.error(err);
					next(err);	
				}
				
			});
		}
	});
};