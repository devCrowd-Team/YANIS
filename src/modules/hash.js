'use strict'

var crypto = require('crypto');
var serverConfig = require('../../server-config');

exports.compute = function(secureKey, hashableValue)
{
	var hashedValue = crypto.createHmac(serverConfig.HashingAlgorithm, secureKey)
				.update(hashableValue)
				.digest("hex");
				
	return hashedValue;
}