'use strict';

const { Storage } = require("@google-cloud/storage");

exports.badge = (event, context) => {
  const build = eventToBuild(event.data);
  setBuildBadge(build);
};

const eventToBuild = (data) => {
  return JSON.parse(new Buffer(data, 'base64').toString());
}

function setBuildBadge(build) {
  const storage = new Storage();
  if (build.status == "SUCCESS") {
    storage
      .bucket(process.env.BUCKET)
      .file(process.env.SUCCESS)
      .copy(storage.bucket(process.env.BUCKET).file(process.env.BADGE));
  } else if (build.status == "TIMEOUT" || build.status == "FAILURE") {
    storage
      .bucket(process.env.BUCKET)
      .file(process.env.FAILURE)
      .copy(storage.bucket(process.env.BUCKET).file(process.env.BADGE));
  }
}
