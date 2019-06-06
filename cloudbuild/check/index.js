'use strict';

const octokit = require('@octokit/rest')();

exports.check = (event, context) => {
  const build = eventToBuild(event.data);
  postBuildStatus(build);
};

const eventToBuild = (data) => {
  return JSON.parse(new Buffer(data, 'base64').toString());
}

function postBuildStatus(build) {
  octokit.authenticate({
    type: 'token',
    token: process.env.TOKEN
  });

  let repo = getRepo(build);
  if (repo === null || repo.site !== 'github') {
    return Promise.resolve();
  }
  let [ state, description ] = buildToGithubStatus(build);
  return octokit.repos.createStatus({
    owner: repo.user,
    repo: repo.name,
    sha: build.sourceProvenance.resolvedRepoSource.commitSha,
    state: state,
    description: description,
    context: process.env.NAME,
    target_url: build.logUrl
  });
}

function getRepo(build) {
  let repoNameRe = /^([^-]*)_([^-]*)_(.*)$/;
  let repoName = build.source.repoSource.repoName;
  let match = repoNameRe.exec(repoName);
  if (!match) {
    console.error(`Cannot parse repoName: ${repoName}`);
    return null;
  }
  return {
    site: match[1],
    user: match[2],
    name: match[3]
  };
}

function buildToGithubStatus(build) {
  let map = {
    QUEUED: ['pending', 'Queued'],
    WORKING: ['pending', 'Working'],
    FAILURE: ['error', 'Failed'],
    INTERNAL_ERROR: ['failure', 'Internal error'],
    CANCELLED: ['failure', 'Cancelled'],
    TIMEOUT: ['failure', 'Timed out'],
    SUCCESS: ['success', 'Success']
  }
  return map[build.status];
}
