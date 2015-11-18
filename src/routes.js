'use strict'

var authenticate = require('./modules/authentication');
var authenticateSample = require('./modules/authenticationForSamples');
var users = require('./modules/users');

exports.SetupFor = function(server){

	server.get('/', function(req,res,next){
		res.send('everything is fine');
		next();
	});
	
	server.get({path: '/IsAuthenticated', flags: 'i'}, authenticate.ByHMac);
	server.get({path: '/SampleRequest', flags : 'i'}, authenticateSample.ComputeSampleHash);
	server.post({path: '/HashedPassword', flags : 'i'}, users.SetHashedPassword)
};