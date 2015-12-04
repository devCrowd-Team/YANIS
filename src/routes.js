'use strict'

function setupFor(server, handle){

	server.get('/', function(req,res,next){
		res.send('everything is fine');
		next();
	});
	
	server.get({path: '/IsAuthenticated', flags: 'i'}, handle.ByHMac);
	server.get({path: '/IsValidToken?:token', flags:'i'}, handle.ValidationOfToken);
	server.post({path: '/HashedPassword', flags : 'i'}, handle.SetHashedPassword);
};

exports.setupFor = setupFor;