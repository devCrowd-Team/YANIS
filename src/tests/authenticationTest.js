'use strict'

var Datastore 		= require('nedb');
var request 		= require('supertest');
var should 			= require('should');
var hash			= require('../modules/hash');
var serverConfig 	= require('../../server-config');
var testDb 			= new Datastore({ filename: '../databases/users.db', autoload: true });

var serverUrl = 'http://' + serverConfig.Host + ":" + serverConfig.Port;

describe('Routing', function(){
    
    beforeEach(function(done){
		
        var testAccount = {
            userId : 'test',
            hashedPassword : serverConfig.SamplePassword
        };
                
        testDb.remove(testAccount, function(err, result)
		{
			if(err){
				throw err;
			} else {
                testDb.insert(testAccount, done);
			}
		});
	});
	
	describe('Authentication', function(){
		it('should authenticate the request and it should not be possible to requesting again', function(done){
			
			var method = "GET";
			var testUri = "testuri"
			var testTimestamp = new Date();
			var expectedSignature = hash.compute(serverConfig.SamplePassword, method+testUri+testTimestamp);
			
			request(serverUrl)
				.get('/IsAuthenticated')
				.set('yanis-method', method)
				.set('yanis-hosturi', testUri)
				.set('yanis-timestamp', testTimestamp)
				.set('authentication','test:' + expectedSignature)
				.expect(200)
				.expect('Content-Type', 'application/json')
				.end(function(err, result){
										
					result.body.should.have.property('success', true);
					result.body.should.have.property('token');
					result.body.token.key.length.should.be.above(0);
					result.body.token.key.should.be.text;
					result.body.token.expired.should.be.exactly("one shot")
					
					request(serverUrl)
						.get('/IsAuthenticated')
						.set('yanis-method', method)
						.set('yanis-hosturi', testUri)
						.set('yanis-timestamp', testTimestamp)
						.set('authentication','test:' + expectedSignature)
						.expect(403)
						.expect('Content-Type', 'application/json')
						.expect({success:false, reason:"Request not authorized"}, done);
				});
		});
		
		it('should get different tokens', function(done){
			
			var method = "GET";
			var testTimestamp = new Date();
			var testUri1 = "different token request 1"
			var testUri2 = "different token request 2"
			
			var signature1 = hash.compute(serverConfig.SamplePassword, method+testUri1+testTimestamp);
			var signature2 = hash.compute(serverConfig.SamplePassword, method+testUri2+testTimestamp);
			
			var token1;
			var token2;
							
			// first request to get valid token
			request(serverUrl)
				.get('/IsAuthenticated')
				.set('yanis-method', method)
				.set('yanis-hosturi', testUri1)
				.set('yanis-timestamp', testTimestamp)
				.set('authentication','test:' + signature1)
				.expect(200)
				.expect('Content-Type', 'application/json')
				.end(function(err, result){
					token1 = result.body.token.key;
					
					// second request to get valid token
					request(serverUrl)
						.get('/IsAuthenticated')
						.set('yanis-method', method)
						.set('yanis-hosturi', testUri2)
						.set('yanis-timestamp', testTimestamp)
						.set('authentication','test:' + signature2)
						.expect(200)
						.expect('Content-Type', 'application/json')
						.end(function(err, result){											
							token2 = result.body.token.key;
							
							token1.should.not.be.equal(token2);
							
							done();
							
						});
				});
		})
		
		it('should deny second request with the same token', function(done){
			
			var validToken;
			var method = 'GET';
			var testUri = "second token request"
			var testTimestamp = new Date();
			
			var expectedSignature = hash.compute(serverConfig.SamplePassword, method+testUri+testTimestamp);
					
					// first request to get valid token
			request(serverUrl)
				.get('/IsAuthenticated')
				.set('yanis-method', method)
				.set('yanis-hosturi', testUri)
				.set('yanis-timestamp', testTimestamp)
				.set('authentication','test:' + expectedSignature)
				.expect(200)
				.expect('Content-Type', 'application/json')
				.end(function(err, result){
										
					validToken = result.body.token.key;
					
					// Request to validate token
					request(serverUrl)
						.get('/IsValidToken')
						.query('token=' + validToken)
						.expect(200)
						.expect('Content-Type', 'application/json')
						.expect({success:true})
						.end(function(err, result){
							
							// Request with same token
							request(serverUrl)
								.get('/IsValidToken')
								.query('token=' + validToken)
								.expect(403)
								.expect('Content-Type', 'application/json')
								.expect({success:false, reason:"Token is expired"}, done);
						});
				});
		});
	});
});