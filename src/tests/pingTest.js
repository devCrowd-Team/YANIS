'use strict'

var request 		= require('supertest');
var should 			= require('should');
var serverConfig 	= require('../../server-config');

var serverUrl = 'http://' + serverConfig.Host + ":" + serverConfig.Port;

describe('Routing', function(){
	describe('Ping', function(){
		it('should return "everything is fine"', function(done){
			
			request(serverUrl)
				.get('/')
				.expect(200, '"everything is fine"', done);
				
		})
	});
});