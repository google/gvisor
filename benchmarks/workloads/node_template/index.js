const app = require('express')();
const path = require('path');
const redis = require('redis');
const srs = require('secure-random-string');

// The hostname is the first argument.
const host_name = process.argv[2];

var client = redis.createClient({host: host_name, detect_buffers: true});

app.set('views', __dirname);
app.set('view engine', 'hbs');

app.get('/', (req, res) => {
  var tmp = [];
  /* Pull four random keys from the redis server. */
  for (i = 0; i < 4; i++) {
    client.get(Math.floor(Math.random() * (100)), function(err, reply) {
      tmp.push(reply.toString());
    });
  }

  res.render('index', {text: tmp});
});

/**
 * Securely generate a random string.
 * @param {number} len
 * @return {string}
 */
function randomBody(len) {
  return srs({alphanumeric: true, length: len});
}

/** Mutates one hundred keys randomly. */
function generateText() {
  for (i = 0; i < 100; i++) {
    client.set(i, randomBody(1024));
  }
}

generateText();
app.listen(8080);
