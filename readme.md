#YANIS - Yet Another Node.JS Identity Server

A light weight Identity Server, who authenticate web requests and provides on shot token. 
You can use this server to identify the requests and use the one shot token to verify the autorized request by an other service.

###Lifecycle of authentication/autorization

Any request needs a set of headers:

* YANIS-Method : Method type of request
* YANIS-HostUri : Uri of request
* YANIS-Timestamp : ISO 8601 UTC Timestamp of request
* Authentication : contains userID and signature of request

The request will validate by checking the header fields and compute the signature from it.
If is valid you will get a one shot request token. This token is valid for a configured time and 
is useful to validate a request against YANIS for one time.

OK, I see, you need a sample.

Imagine you have an enterprise application with a lot of internal services. Sometime you have to provide an accepoint for your customers.
This accesspoint will take any request and sends the header fields to YANIS, provided in your internal environment, for validation. If
the request valid the accesspoint use the request token to mark this request as valid. Now your accesspoint routes the request data to one of
your internal service. This service use the token to ask YANIS: "is this request validated by you?". Yes, and now YANIS can answer, yes or now. 
But it can answer 'yes' only once, the token expires after that. 

###Signature

The signature is a part of Authentication header and have to created by hashing header values with a secret value, known only by requester and YANIS.
... HMac 512 and hashed password of requester
... sample code

#### next steps:
* Uri should be the real call uri
* md5 hashing of content (GET will be empty)
* message representation should contain: method, md5 of content, accept header, called uri, ISO 8601 UTC timestamp and a public key of user
* any user can decide which encryption wants to use
* OAuth2 integration
* Web UI to manage Keys and Users
* one shot token for URIs (check the token against an URI)
* ~~remove SampleRequest path~~
* help page
* ES6 style
