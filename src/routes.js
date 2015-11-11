'use strict'

var authenticate = require('./modules/authentication');
var authenticateSample = require('./modules/authenticationForSamples');

exports.SetupFor = function(server){

	server.get('/', function(req,res,next){
		res.send('everything is fine');
		next();
	});
	
	server.get({path: '/IsAuthenticated', flags: 'i'}, authenticate.ByHMac);
	server.get({path: '/SampleRequest', flags : 'i'}, authenticateSample.ComputeSampleHash);
};