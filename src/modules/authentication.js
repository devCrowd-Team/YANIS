'use strict'

var Q = require('Q');
var bunyan = require('bunyan');
var crypto = require('crypto');
var users = require('./users');
var packageConfig = require('../../package');
var serverConfig = require('../../server-config');

var autorizationHeaderFields = serverConfig.AutorizationHeaderFields;
var logging = bunyan.createLogger({name: packageConfig.name});

exports.ByHMac = function(req, res, next){
		
	validate(req)
	 .then(getHashedPassword)
	 .then(authenticate)
	 .then(function(signature){
		 sendAuthorization(signature, res, next);
	 })
	 .fail(function(error)
	 {
		logging.info("Request not authorized")
		logging.error(error);
		
		res.writeHeader(403,{"Content-Type":"text/html"})
		res.end("You are not authorized");
		next();
	 });
};

function validate(request) {
	logging.info("Request will validate");
	
	var d = Q.defer();
	
	var method = request.headers[autorizationHeaderFields.Method];
	var uri = request.headers[autorizationHeaderFields.HostUri];
	var timestamp = request.headers[autorizationHeaderFields.Timestamp];
	var authorization = request.headers[autorizationHeaderFields.Authentication];
	var userId, signature;
	
	if(method == null){
		d.reject(new Error("Invalid YANIS-Method Header"));
	}
	
	if(uri == null){
		d.reject(new Error("Invalid YANIS-HostUri Header"));
	}
	
	if(timestamp == null){
		d.reject(new Error("Invalid YANIS-Timestamp Header"))
	}
	
	if(authorization == null){		
		d.reject(new Error("Invalid YANIS-Authentication Header"))
	} else {
		var authorizationParts = authorization.split(":");
		
		userId = authorizationParts[0];
		signature = authorizationParts[1];
	}
	
	d.resolve({
		method     : method,
		uri        : uri,
		userId     : userId,
		signature  : signature,
		timestamp  : timestamp
	});
	
	return d.promise;
};

function getHashedPassword(requestParameter){
	var d = Q.defer();
	
	users.GetHashedPasswordFor(requestParameter.userId)
		.then(function(hashedPassword){
			
			requestParameter.hashedPassword = hashedPassword;
			
			d.resolve(requestParameter);
		},  d.reject);
		
	return d.promise;
}

function authenticate(requestParameter) {
	logging.info("Authenticate Request " + requestParameter);
	
	var d = Q.defer();
	
	var hashableMessage = requestParameter.method
						+ requestParameter.uri
						+ requestParameter.timestamp;
						
	var signatureOfRequestParameters = 
			crypto.createHmac(serverConfig.HashingAlgorithm, requestParameter.hashedPassword)
				.update(hashableMessage)
				.digest("hex");
											 
	if(signatureOfRequestParameters === requestParameter.signature){
		d.resolve(requestParameter.signature);
	} else {
		d.reject(new Error("Request is not authenticated"));
	}
	
	return d.promise;
};

function sendAuthorization(signature,res,next){
	logging.info("Request authorized with signature %s", signature)
	
	var deferred = Q.defer();
		
	res.writeHeader(200,{"Content-Type":"text/html"})
	res.end("You are authorized");
	next();
		
	deferred.resolve();

	return deferred.promise;
};