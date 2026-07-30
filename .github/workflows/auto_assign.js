/**
 * Auto-assigns maintainers from reviewer.json to incoming Pull Requests by
 * combining GitHub blame suggestions with a randomized roster fallback.
 *
 * This function is executed as a GitHub Action. It parses the active
 * maintainers roster, filters out the PR author and bots, and assigns up to
 * two reviewers: prioritizing one suggested domain expert (if available) and
 * randomly selecting fallback reviewer(s) from the remaining eligible roster.
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

  // Fetch suggested reviewers via GraphQL
  let suggestedLogins = [];
  try {
    const query = `
        query($owner: String!, $repo: String!, $prNum: Int!) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $prNum) {
              suggestedReviewers {
                reviewer {
                  login
                }
              }
            }
          }
        }
      `;
    const gqlResult = await github.graphql(query, {owner, repo, prNum});
    suggestedLogins = (gqlResult.repository.pullRequest.suggestedReviewers ||
                       []).map(s => s.reviewer.login);
  } catch (error) {
    core.warning(`Notice: Could not fetch suggested reviewers via GraphQL: ${
        error.message}`);
  }

  console.log('Suggested reviewers: ', suggestedLogins);

  // Filter out suggested reviewers that are not in the eligible approvers list
  const eligibleSuggestions =
      suggestedLogins.filter(login => eligibleApprovers.includes(login));

  const shuffle = (array) => {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  const selectedReviewers = [];

  if (eligibleSuggestions.length > 0) {
    const shuffledSuggestions = shuffle(eligibleSuggestions);
    selectedReviewers.push(shuffledSuggestions[0]);
    console.log(`Selected suggested reviewer: ${shuffledSuggestions[0]}`);
  }

  // Select from the remaining eligible approvers
  const remainingEligible =
      eligibleApprovers.filter(login => !selectedReviewers.includes(login));
  if (remainingEligible.length > 0 && selectedReviewers.length < 2) {
    const shuffledRemaining = shuffle(remainingEligible);
    const needed =
        Math.min(2 - selectedReviewers.length, shuffledRemaining.length);
    for (let i = 0; i < needed; i++) {
      selectedReviewers.push(shuffledRemaining[i]);
      console.log(`Selected fallback roster reviewer: ${shuffledRemaining[i]}`);
    }
  }

  // Apply assignment
  try {
    await github.rest.pulls.requestReviewers(
        {owner, repo, pull_number: prNum, reviewers: selectedReviewers});
    console.log(`Successfully requested review from [${
        selectedReviewers.join(', ')}] for PR #${prNum}`);
  } catch (error) {
    core.setFailed(`Failed to apply assignment API calls: ${error.message}`);
    return;
  }
};
