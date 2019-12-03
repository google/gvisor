'use strict';

var start = new Date().getTime();

// Load dependencies to simulate an average nodejs app.
var req_0 = require('async');
var req_1 = require('bluebird');
var req_2 = require('firebase');
var req_3 = require('firebase-admin');
var req_4 = require('@google-cloud/container');
var req_5 = require('@google-cloud/logging');
var req_6 = require('@google-cloud/monitoring');
var req_7 = require('@google-cloud/spanner');
var req_8 = require('lodash');
var req_9 = require('mailgun-js');
var req_10 = require('request');
var express = require('express');
var app = express();

var loaded = new Date().getTime() - start;
app.get('/', function(req, res) {
  res.send('Hello World!<br>Loaded in ' + loaded + 'ms');
});

console.log('Loaded in ' + loaded + ' ms');
app.listen(8080, function() {
  console.log('Listening on port 8080...');
});
