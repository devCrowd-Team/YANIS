'use strict'

var Q = require('Q');
var crypto = require('crypto');

exports.ComputeSampleHash = function (req, res, next){
	validateSample(req)
	 .then(authenticateSample)
	 .then(function(signature){
		 sendSampleAuthorization(signature, res, next);
	 })
	 .fail(function(error)
	 {
		res.writeHeader(403,{"Content-Type":"text/json"})
		res.end("Invalid Request cause: " + error);
		next();
	 });
};

function validateSample(request) {
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

function authenticateSample(requestParameter) {
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

function sendSampleAuthorization(signature,res,next){
	var deferred = Q.defer();
		
	res.writeHeader(200,{"Content-Type":"application/json"});
	
	var json = JSON.stringify(signature);
	
	res.end(json);
	next();
		
	deferred.resolve();

	return deferred.promise;
};