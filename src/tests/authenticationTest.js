'use strict'

var Datastore 		= require('nedb');
var testDb 			= new Datastore({ filename: 'test.db', autoload: true });
var request 		= require('supertest');
var should 			= require('should');
var serverConfig 	= require('../../server-config');

var serverUrl = 'http://' + serverConfig.Host + ":" + serverConfig.Port;

describe('Routing', function(){
	
	before(function(done){
		
		var testAccount = {
			userId : 'test',
			hashedPassword : serverConfig.SamplePassword
		};
	
		testDb.insert(testAccount, function(err, newAccount){
			if(err){
				throw err;
			} else {
				done();
			}
		});
	});
	
	describe('Authentication', function(){
		it('should authenticate the request and it is not possible to requesting again', function(done){
			
			var expectedSignature;
			var method = 'GET';
			var testUri = "testuri"
			var testTimestamp = new Date();
			
			// Signatur über die Sample Route beschaffen
			request(serverUrl)
				.get('/SampleRequest')
				.set('yanis-method',method)
				.set('yanis-hosturi',testUri)
				.set('yanis-timestamp', testTimestamp)
				.end(function(err, result){
					
					result.body.password.should.be.exactly(serverConfig.SamplePassword);
					expectedSignature = result.body.signature;
					
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
							result.body.token.length.should.be.above(0);
							result.body.token.should.be.text;
							
							request(serverUrl)
								.get('/IsAuthenticated')
								.set('yanis-method', method)
								.set('yanis-hosturi', testUri)
								.set('yanis-timestamp', testTimestamp)
								.set('authentication','test:' + expectedSignature)
								.expect(403)
								.expect('Content-Type', 'application/json')
								.expect({success:false}, done);
						});
				});
		});
		
		it('should get different tokens', function(done){
			var signature1;
			var token1;
			var timestamp1 = new Date();
			var signature2;
			var token2;
			var timestamp2 = new Date();
			
			
			// Signatur über die Sample Route beschaffen
			request(serverUrl)
				.get('/SampleRequest')
				.set('yanis-method',"GET")
				.set('yanis-hosturi',"different token request 1")
				.set('yanis-timestamp', timestamp1)
				.end(function(err, result){
					signature1 = result.body.signature;
					
					// Signatur über die Sample Route beschaffen
					request(serverUrl)
						.get('/SampleRequest')
						.set('yanis-method',"GET")
						.set('yanis-hosturi',"different token request 2")
						.set('yanis-timestamp', timestamp2)
						.end(function(err, result){
							signature2 = result.body.signature;
							
							// first request to get valid token
							request(serverUrl)
								.get('/IsAuthenticated')
								.set('yanis-method',"GET")
								.set('yanis-hosturi',"different token request 1")
								.set('yanis-timestamp', timestamp1)
								.set('authentication','test:' + signature1)
								.expect(200)
								.expect('Content-Type', 'application/json')
								.end(function(err, result){
									token1 = result.body.token;
									
									// second request to get valid token
									request(serverUrl)
										.get('/IsAuthenticated')
										.set('yanis-method', "GET")
										.set('yanis-hosturi', "different token request 2")
										.set('yanis-timestamp', timestamp2)
										.set('authentication','test:' + signature2)
										.expect(200)
										.expect('Content-Type', 'application/json')
										.end(function(err, result){											
											token2 = result.body.token;
											
											token1.should.not.be.equal(token2);
											
											done();
											
										});
									
								});
						});
				});
			
		})
		
		it('should deny second request with the same token', function(done){
			var expectedSignature;
			var validToken;
			var method = 'GET';
			var testUri = "second token request"
			var testTimestamp = new Date();
			
			// Signatur über die Sample Route beschaffen
			request(serverUrl)
				.get('/SampleRequest')
				.set('yanis-method',method)
				.set('yanis-hosturi',testUri)
				.set('yanis-timestamp', testTimestamp)
				.end(function(err, result){
					
					result.body.password.should.be.exactly(serverConfig.SamplePassword);
					expectedSignature = result.body.signature;
					
				});
			
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
										
					result.body.should.have.property('success', true);
					result.body.should.have.property('token');
					result.body.token.length.should.be.above(0);
					result.body.token.should.be.text;
					
					validToken = result.body.token;
					
				});
			
			// Request to validate token
			request(serverUrl)
				.get('/IsValidToken')
				.query('token=' + validToken)
				.expect(200)
				.expect('Content-Type', 'application/json')
				.expect({success:true});
			
			// Request with same token
			request(serverUrl)
				.get('/IsValidToken')
				.query('token=' + validToken)
				.expect(403)
				.expect('Content-Type', 'application/json')
				.expect({success:false}, done);
		});
		
	});
	
	after(function(done){
		testDb.remove({userId:'test'}, function(err, result)
		{
			if(err){
				throw err;
			} else {
				done();
			}
		});
	});
	
});