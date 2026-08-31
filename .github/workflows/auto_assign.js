const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Auto-assigns maintainers from governance/maintainers.yaml and areas.yaml to
 * incoming Pull Requests by combining area specialization with a randomized roster fallback.
 *
 * This function is executed as a GitHub Action. It parses the active
 * maintainers roster, filters out the PR author and bots, and assigns up to
 * two reviewers: prioritizing one suggested domain expert (if available) and
 * randomly selecting fallback reviewer(s) from the remaining eligible roster
 * to encourage knowledge sharing.
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
  const authorLower = author.toLowerCase();

  // Filter out automated PRs
  if (pr.user.type === 'Bot') {
    return;
  }

  // Check if already assigned
  if ((pr.requested_reviewers || []).length > 0 ||
      (pr.assignees || []).length > 0) {
    return;
  }

  // Read active maintainers and areas from governance YAML files
  let maintainersData, areasData;
  try {
    const workspace = process.env.GITHUB_WORKSPACE || '.';
    maintainersData = yaml.load(
        fs.readFileSync(
            path.join(workspace, 'governance/maintainers.yaml'), 'utf8'));
    areasData = yaml.load(
        fs.readFileSync(
            path.join(workspace, 'governance/areas.yaml'), 'utf8'));
  } catch (error) {
    core.setFailed(`Could not load governance YAML files: ${error.message}`);
    return;
  }

  // Filter for active maintainers and build area mapping
  const maintainersByArea = new Map();
  const eligibleApprovers = [];
  for (const m of maintainersData?.maintainers || []) {
    if (m.status === 'ACTIVE' && m.github && m.github.toLowerCase() !== authorLower) {
      eligibleApprovers.push(m.github);
      for (const area of (m.areas || [])) {
        if (!maintainersByArea.has(area)) {
          maintainersByArea.set(area, []);
        }
        maintainersByArea.get(area).push(m.github);
      }
    }
  }

  if (eligibleApprovers.length === 0) {
    core.setFailed('No eligible approvers available to assign.');
    return;
  }

  // Find all specialists for areas covering the changed files
  let eligibleAreaSpecialists = [];
  try {
    const changedFiles = await github.paginate(github.rest.pulls.listFiles, {
      owner,
      repo,
      pull_number: prNum,
      per_page: 100,
    });

    const filePaths = changedFiles.map(f => '/' + f.filename);
    const matchedAreas = (areasData?.areas || [])
        .filter(area => area.paths?.some(p => filePaths.some(f => f === p || f.startsWith(p + '/'))))
        .map(area => area.name);

    eligibleAreaSpecialists = [
      ...new Set(matchedAreas.flatMap(area => maintainersByArea.get(area) || [])
          .filter(login => eligibleApprovers.includes(login))),
    ];
  } catch (error) {
    core.warning(
        `Notice: Could not match changed files to areas: ${error.message}`);
  }

  const shuffle = (array) => {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  const selectedReviewers = [];

  // Prioritize 1 specialist from the matched areas
  if (eligibleAreaSpecialists.length > 0) {
    const specialistsToAssign = shuffle(eligibleAreaSpecialists).slice(0, 1);
    for (const specialist of specialistsToAssign) {
      selectedReviewers.push(specialist);
      console.log(`Selected area specialist: ${specialist}`);
    }
  }

  // Fallback: Fill remaining slot(s) (up to 2 total reviewers) from general eligible roster
  const selectedReviewersLower = selectedReviewers.map(r => r.toLowerCase());
  const remainingEligible = eligibleApprovers.filter(
      login => !selectedReviewersLower.includes(login.toLowerCase()));
  if (remainingEligible.length > 0 && selectedReviewers.length < 2) {
    const needed = 2 - selectedReviewers.length;
    const fallbackToAssign = shuffle(remainingEligible).slice(0, needed);
    for (const reviewer of fallbackToAssign) {
      selectedReviewers.push(reviewer);
      console.log(`Selected fallback roster reviewer: ${reviewer}`);
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
