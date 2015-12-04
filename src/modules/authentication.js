'use strict'

var Q 				= require('q');
var bunyan 			= require('bunyan');
var uuid 			= require('uuid');
var cache 			= require('./cache');
var hash 			= require('./hash');
var users 			= require('./users');
var packageConfig 	= require('../../package');
var serverConfig 	= require('../../server-config');

var autorizationHeaderFields = serverConfig.AutorizationHeaderFields;
var logging = bunyan.createLogger({name: packageConfig.name});

exports.byHMac = function(req, res, next){
		
	validate(req)
	 .then(function(reqParameters){
		 cache.add(reqParameters.signature);
		 return reqParameters;
	 })
	 .then(getHashedPassword)
	 .then(authenticate)
	 .then(function(signature){
		 
		logging.info("Request authorized with signature %s", signature);
		
		var token = uuid.v4();
		cache.add(token)
		success(token, res,next);
	 })
	 .fail(function(error)
	 {
		logging.warn("Request not authorized")
		logging.error(error);
		
		failure("Request not authorized", res, next);
	 });
};

exports.validateToken = function(req, res, next){
	var token = req.query.token;
	
	if(cache.contains(token)){
		cache.remove(token);
		logging.info("Token %s removed", token)
		success(token, res, next);
	} else{
		logging.warn("Token %s expired", token)
		failure("Token is expired", res, next);	
	}
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
	
	if( ! isDateValid(timestamp)){
		d.reject(new Error("Invalid Timestamp"))
	}
	
	if(authorization == null){		
		d.reject(new Error("Invalid Authentication Header"))
	} else {
		var authorizationParts = authorization.split(":");
		
		userId = authorizationParts[0];
		signature = authorizationParts[1];
		
		logging.info(signature);
	}
	
	if(cache.contains(signature)){
		d.reject(new Error("Invalid Signature"))
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

function isDateValid(timestamp){

	var parsedTimestamp = Date.parse(timestamp);
	
	if(parsedTimestamp)
	{
		var serverTimestamp = Date.now();
		
		if((parsedTimestamp < cacheDurationBefore(serverTimestamp)) 
		|| (parsedTimestamp > cacheDurationAfter(serverTimestamp))){
			return false;
		}
		
		return true
	} 
	
	return false;
}

function cacheDurationBefore(serverDate){
	
	var cacheDuration = parseInt(serverConfig.CacheDuration);
	
	return serverDate - cacheDuration;
}

function cacheDurationAfter(serverDate){
	
	var cacheDuration = parseInt(serverConfig.CacheDuration);
	
	return serverDate + cacheDuration;
}

function getHashedPassword(requestParameters){
	var d = Q.defer();
	
	users.getHashedPasswordFor(requestParameters.userId)
		.then(function(hashedPassword){
			
			requestParameters.hashedPassword = hashedPassword;
			
			d.resolve(requestParameters);
		},  d.reject);
		
	return d.promise;
}

function authenticate(requestParameter) {
	logging.info("Authenticate Request " + requestParameter);
	
	var d = Q.defer();
	
	var hashableMessage = requestParameter.method
						+ requestParameter.uri
						+ requestParameter.timestamp;
						
	var signatureOfRequestParameters = hash.compute(requestParameter.hashedPassword, hashableMessage);
											 
	if(signatureOfRequestParameters === requestParameter.signature){
		d.resolve(requestParameter.signature);
	} else {
		d.reject(new Error("Request is not authenticated"));
	}
	
	return d.promise;
};

function success(token, res, next){
	res.writeHeader(200,{"Content-Type":"application/json"});
	res.end(JSON.stringify({success:true, token:{key:token, expired:"one shot"}}));
	next();
}

function failure(reason, res, next){
	res.writeHeader(403,{"Content-Type":"application/json"});
	res.end(JSON.stringify({success:false, reason:reason}));
	next();
}