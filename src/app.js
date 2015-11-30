'use strict'

var restify 			= require('restify');
var bunyan 				= require('bunyan');

var serverConfig 		= require('../server-config');
var packageConfig 		= require('../package');

var routes 				= require('./routes');
var authenticate 		= require('./modules/authentication');
var authenticateSample 	= require('./modules/authenticationForSamples');
var users 				= require('./modules/users');

var logging = bunyan.createLogger({name: packageConfig.name})

/* Create Server */
var server = restify.createServer({
	log : logging
});

/* Setup Server */
server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(restify.authorizationParser());

/* -- Logging -- */
server.use(function logger(req, res, next){
	logging.info('Method: %s -- Url: %s', req.method, res.uri);
	next();
});
/* -- Unexpected Exception Handling -- */
server.on('uncaughtException', function(req, res, route, error){
	logging.error(error);
	res.writeHead(500, {"Conent-Type":"text/html"})
	res.end("Sorry, this should never happen. " + error.stack);	
});

/* -- Routes -- */
var handlers = {
	ByHMac : authenticate.ByHMac,
	ComputeSampleHash : authenticateSample.ComputeSampleHash,
	SetHashedPassword : users.SetHashedPassword
}

routes.SetupFor(server, handlers);

/* Start Server */
server.listen(serverConfig.Port, serverConfig.Host, function(){
	console.log('%s listening at %s', serverConfig.Name, server.url);
	logging.info('Server is online');
});