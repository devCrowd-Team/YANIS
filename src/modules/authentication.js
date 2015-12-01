'use strict'

var Q 				= require('q');
var bunyan 			= require('bunyan');
var crypto 			= require('crypto');
var cache 			= require('memory-cache');
var uuid 			= require('uuid');
var users 			= require('./users');
var packageConfig 	= require('../../package');
var serverConfig 	= require('../../server-config');

var autorizationHeaderFields = serverConfig.AutorizationHeaderFields;
var logging = bunyan.createLogger({name: packageConfig.name});

exports.byHMac = function(req, res, next){
		
	validate(req)
	 .then(putSignatureIntoCache)
	 .then(getHashedPassword)
	 .then(authenticate)
	 .then(function(signature){
		 sendAuthorization(signature, res, next);
	 })
	 .fail(function(error)
	 {
		sendRejection(error, res, next);
	 });
};

exports.validateToken = function(req, res, next){
	var token = req.query.token;
	
	if(isTokenValid(token)){
		removeFromCacheAndSendSuccess(token, res, next);
	}
	
	//sendTokenFailure();
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
	
	if( ! isSignatureValid(signature)){
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

function isSignatureValid(signature){
	if(cache.get(signature)){
		logging.warn("Signature already cached")
		
		return false;
	} 
	
	return true;
}

function isTokenValid(token){
		
	if(cache.get(token)){
		return true;
	} 
	
	return false;
}

function putSignatureIntoCache(reqestParameters){
	if(cache.get(reqestParameters.signature) == null){
		cache.put(reqestParameters.signature, reqestParameters.signature, serverConfig.CacheDuration)	
	}
	
	return reqestParameters;
}

function putTokenIntoCache(token){
	cache.put(token, token, serverConfig.CacheDuration);
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

function generateNewTokenAndCacheIt(){
	var id = uuid.v4();
	putTokenIntoCache(id);
	
	return id;
}

function sendAuthorization(signature,res,next){
	logging.info("Request authorized with signature %s", signature)
	
	var deferred = Q.defer();
	
	var token = generateNewTokenAndCacheIt();
	
	res.writeHeader(200,{"Content-Type":"application/json"})
	res.end(JSON.stringify({success:true, token:token}));
	
	next();
		
	deferred.resolve();

	return deferred.promise;
};

function sendRejection(err, res, next){
	logging.info("Request not authorized")
	logging.error(err);
	
	res.writeHeader(403,{"Content-Type":"application/json"})
	res.end(JSON.stringify({success : false}));
	next();
}

function removeFromCacheAndSendSuccess(token, res, next){
	
	cache.del(token);
	logging.info("Token %s removed", token)
	
	res.writeHeader(200,{"Content-Type":"application/json"});
	res.end(JSON.stringify({success:true}));
}