/**
 * Auto-assigns maintainers from reviewer.json to incoming Pull Requests in a
 * round-robin fashion.
 *
 * This function is executed as a GitHub Action. It parses the active
 * maintainers roster, filters out the PR author and bots, and assigns a
 * reviewer deterministically using a modulo operation on the Pull Request ID.
 *
 * @param {{
 *   github: !Object,
 *   context: !Object,
 *   core: !Object,
 * }} params - The injected actions/github-script objects.
 *     github: An authenticated Octokit REST client.
 *     context: The GitHub Actions workflow context and payload.
 *     core: The GitHub Actions core toolkit for logging/errors.
 */
module.exports = async ({github, context, core}) => {
  const {owner, repo} = context.repo;
  const prNum = context.payload.pull_request.number;
  const pr = context.payload.pull_request;
  const author = pr.user.login;

  // Filter out automated PRs
  if (pr.user.type === 'Bot') {
    return;
  }

  // Check if already assigned
  if ((pr.requested_reviewers || []).length > 0 ||
      (pr.assignees || []).length > 0) {
    return;
  }

  // Read active maintainers from .github/reviewer.json file
  let approvers = {};
  try {
    approvers = require('../reviewer.json');
  } catch (error) {
    core.setFailed(`Could not load .github/reviewer.json: ${error.message}`);
    return;
  }

  if (!approvers || typeof approvers !== 'object' ||
      Object.keys(approvers).length === 0) {
    core.setFailed('No team members found in .github/reviewer.json.');
    return;
  }

  // Filter out the PR author and inactive/OOO members (which is manually
  // setting to false in reviewer.json now).
  const eligibleApprovers = Object.keys(approvers).filter(
      login => approvers[login] === true && login !== author);
  if (eligibleApprovers.length === 0) {
    core.setFailed('No eligible approvers available to assign.');
    return;
  }

  // Basic Round Robin
  const selectedMatch = eligibleApprovers[prNum % eligibleApprovers.length];

  // Apply assignment
  try {
    await github.rest.pulls.requestReviewers(
        {owner, repo, pull_number: prNum, reviewers: [selectedMatch]});
    console.log(`Successfully requested review from ${
        selectedMatch} for PR #${prNum}`);
  } catch (error) {
    core.setFailed(`Failed to apply assignment API calls: ${error.message}`);
    return;
  }
};
