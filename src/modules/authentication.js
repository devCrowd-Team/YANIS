'use strict'

var Q = require('Q');
var bunyan = require('bunyan');
var crypto = require('crypto');
var users = require('./users');
var packageConfig = require('../../package');

var logging = bunyan.createLogger({name: packageConfig.name});

exports.ByHMac = function(req, res, next){
		
	validate(req)
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

exports.ComputeSampleHash = function (req, res, next){
	validateSample(req)
	 .then(authenticateSample)
	 .then(function(signature){
		 sendSampleAuthorization(signature, res, next);
	 })
	 .fail(function(error)
	 {
		logging.info("Request not authorized")
		logging.error(error);
		
		res.writeHeader(403,{"Content-Type":"text/html"})
		res.end("Invalid Request cause: " + error);
		next();
	 });
};

function validate(request) {
	logging.info("Request will validate");
	
	var d = Q.defer();
	
	var method = request.headers['yanis-method'];
	var uri = request.headers['yanis-uri'];
	var parameters = request.headers['yanis-parameters'];
	var timestamp = request.headers['yanis-timestamp'];
	var authorization = request.headers['authentication'];
	var userId, signature;
	
	if(method == null){
		d.reject(new Error("Invalid YANIS-Method Header"));
	}
	
	if(uri == null){
		d.reject(new Error("Invalid YANIS-Uri Header"));
	}
	
	if(parameters == null){
		d.reject(new Error("Invalid YANIS-Parameters Header"))
	}
	
	if(timestamp == null){
		d.reject(new Error("Invalid YANIS-Timestamp Header"))
	}
	
	if(authorization == null){		
		d.reject(new Error("Invalid Authentication Header"))
	} else {
		var authorizationParts = authorization.split(":");
		
		userId = authorizationParts[0];
		signature = authorizationParts[1];
	}
	
	d.resolve({
		method     : method,
		uri        : uri,
		parameters : parameters,
		userId     : userId,
		signature  : signature,
		timestapm  : timestamp
	});
	
	return d.promise;
};

function validateSample(request) {
	logging.info("Request will validate");
	
	var d = Q.defer();
	
	var method = request.headers['yanis-method'];
	var uri = request.headers['yanis-uri'];
	var parameters = request.headers['yanis-parameters'];
	var timestamp = request.headers['yanis-timestamp'];
	
	if(method == null){
		d.reject(new Error("Invalid YANIS-Method Header"));
	}
	
	if(uri == null){
		d.reject(new Error("Invalid YANIS-Uri Header"));
	}
	
	if(parameters == null){
		d.reject(new Error("Invalid YANIS-Parameters Header"))
	}
	
	if(timestamp == null){
		d.reject(new Error("Invalid YANIS-Timestamp Header"))
	}
	
	d.resolve({
		method     : method,
		uri        : uri,
		parameters : parameters,
		timestamp  : timestamp
	});
	
	return d.promise;
};

function authenticate(requestParameter) {
	logging.info("Authenticate Request " + requestParameter);
	
	var d = Q.defer();
	var usersPassword = users.GetHashedPasswordFor(requestParameter.userId);
	
	var hashableMessage = requestParameter.method
						+ requestParameter.timestamp
						+ requestParameter.uri
						+ requestParameter.parameters;
						
	var signatureOfRequestParameters = crypto.createHmac("sha256", usersPassword)
											 .update(hashableMessage)
											 .digest("hex");
											 
	if(signatureOfRequestParameters === requestParameter.signature){
		d.resolve(requestParameter.signature);
	} else {
		d.reject(new Error("Request is not authenticated"));
	}
	
	return d.promise;
};

function authenticateSample(requestParameter) {
	logging.info("Authenticate Request " + requestParameter);
	
	var d = Q.defer();
	
	var password = "test";
	var hashableMessage = requestParameter.method
						+ requestParameter.timestamp
						+ requestParameter.uri
						+ requestParameter.parameters;
						
	var signatureOfRequestParameters = 
			crypto.createHmac("sha256", password)
				  .update(hashableMessage)
				  .digest("hex");
											 
	d.resolve({
		signature : signatureOfRequestParameters,
		password : password
	});
	
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

function sendSampleAuthorization(signature,res,next){
	logging.info("Request authorized with signature %s", signature);
	
	var deferred = Q.defer();
		
	res.writeHeader(200,{"Content-Type":"application/json"});
	
	var json = JSON.stringify(signature);
	
	res.end(json);
	next();
		
	deferred.resolve();

	return deferred.promise;
};