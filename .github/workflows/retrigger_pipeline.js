/**
 * Creates a new Buildkite `pipeline` build in certain situations where Buildkite
 * webhook triggers cannot safely do so.
 *
 * Currently, there is only one such case: when an approved commit gets pushed with
 * a rebase, GitHub automatically carries over the approval to the new PR head commit.
 * However, this carried-over approval does *not* trigger a review webhook event to
 * Buildkite, so Buildkite does not trigger a re-run of `pipeline`. We also can't make
 * `push` events trigger `pipeline` in Buildkite, since we need to check if the commit
 * is approved first. So we have this hacky script to re-trigger whenever an approval
 * is carried over.
 *
 * @param {{
 *   github: !Object,
 *   context: !Object,
 *   core: !Object,
 *   buildkiteToken: (string|undefined),
 * }} params - The injected actions/github-script objects.
 *     github: An authenticated Octokit REST client.
 *     context: The GitHub Actions workflow context and payload.
 *     core: The GitHub Actions core toolkit for logging/errors.
 *     buildkiteToken: A Buildkite API token that can create Pipeline builds.
 */
module.exports = async ({github, context, core, buildkiteToken}) => {
  const {owner, repo} = context.repo;
  const pr = context.payload.pull_request;
  const sha = pr.head.sha;

  // Is the new head commit approved? Reviews are listed in chronological
  // order, so each one supersedes its reviewer's earlier opinion.
  const reviews = await github.paginate(
      github.rest.pulls.listReviews,
      {owner, repo, pull_number: pr.number, per_page: 100});
  const approvers = new Set();
  for (const r of reviews) {
    if (r.state === 'COMMENTED' || r.state === 'PENDING') {
      continue;
    }
    if (r.state === 'APPROVED' && r.commit_id === sha) {
      approvers.add(r.user?.id);
    } else {
      // Changes requested, a dismissal, or an approval of another commit.
      approvers.delete(r.user?.id);
    }
  }
  if (approvers.size === 0) {
    core.info(`${sha} isn't approved; not running buildkite/pipeline/pr.`);
    return;
  }

  // Skip if a Pipeline build already exists for this commit.
  const statuses = await github.paginate(
      github.rest.repos.listCommitStatusesForRef,
      {owner, repo, ref: sha, per_page: 100});
  if (statuses.some((s) => s.context === 'buildkite/pipeline/pr')) {
    core.info(`${sha} already has a Pipeline build.`);
    return;
  }

  if (!pr.head.repo) {
    core.info('The PR\'s head repository no longer exists.');
    return;
  }
  if (!buildkiteToken) {
    core.setFailed('buildkiteToken is not set.');
    return;
  }

  // Create a PR build for the commit checked above.
  const crossRepo = pr.head.repo.full_name !== pr.base.repo.full_name;
  const build = {
    commit: sha,
    branch: crossRepo ? `${pr.head.repo.owner.login}:${pr.head.ref}` :
                        pr.head.ref,
    message: pr.title,
    pull_request_id: pr.number,
    pull_request_base_branch: pr.base.ref,
    pull_request_repository: pr.head.repo.clone_url,
  };
  const resp = await fetch(
      'https://api.buildkite.com/v2/organizations/gvisor/pipelines/pipeline/builds',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${buildkiteToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(build),
      });
  if (!resp.ok) {
    core.setFailed(`Buildkite returned ${resp.status}: ${await resp.text()}`);
    return;
  }
  const created = await resp.json();
  core.info(`Created Pipeline build #${created.number} for ${sha}: ${created.web_url}`);
};
