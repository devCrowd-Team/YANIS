'use strict'

var cache 			= require('memory-cache');
var serverConfig 	= require('../../server-config');

exports.contains = function(value){
	if(cache.get(value)){
		return true;
	}
	
	return false;
}

exports.add = function(value){
	cache.put(value, value, serverConfig.CacheDuration)
}

exports.remove = function(value){
	cache.del(value);
}

