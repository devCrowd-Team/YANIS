'use strict'

var Q = require('q');
var crypto = require('crypto');
var serverConfig = require('../../server-config');
var autorizationHeaderFields = serverConfig.AutorizationHeaderFields;

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
	
	var method = request.headers[autorizationHeaderFields.Method];
	var uri = request.headers[autorizationHeaderFields.HostUri];
	var timestamp = request.headers[autorizationHeaderFields.Timestamp];
	
	if(method == null){
		d.reject(new Error("Invalid YANIS-Method Header"));
	}
	
	if(uri == null){
		d.reject(new Error("Invalid YANIS-HostUri Header"));
	}
	
	if(timestamp == null){
		d.reject(new Error("Invalid YANIS-Timestamp Header"))
	}
	
	d.resolve({
		method     : method,
		uri        : uri,
		timestamp  : timestamp
	});
	
	return d.promise;
};

function authenticateSample(requestParameter) {
	var d = Q.defer();
	
	var algorithm = serverConfig.HashingAlgorithm;
	var samplePassword = serverConfig.SamplePassword;
	var hashableMessage = requestParameter.method
						+ requestParameter.uri
						+ requestParameter.timestamp;
	
	var signatureOfRequestParameters = 
			crypto.createHmac(algorithm, samplePassword)
				  .update(hashableMessage)
				  .digest("hex");
											 
	d.resolve({
		signature : signatureOfRequestParameters,
		password : samplePassword,
		algorithm : algorithm
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