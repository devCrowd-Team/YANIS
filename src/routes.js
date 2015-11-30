'use strict'



exports.SetupFor = function(server, handle){

	server.get('/', function(req,res,next){
		res.send('everything is fine');
		next();
	});
	
	server.get({path: '/IsAuthenticated', flags: 'i'}, handle.ByHMac);
	server.get({path: '/SampleRequest', flags : 'i'}, handle.ComputeSampleHash);
	server.post({path: '/HashedPassword', flags : 'i'}, handle.SetHashedPassword)
};