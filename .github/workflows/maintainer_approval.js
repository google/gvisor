const {execFileSync} = require('child_process');
const path = require('path');

// The families of base branches whose rules require a status. Each family has
// its own status, because an approval is for the changes between a base branch
// and the head commit. A status of one family does not satisfy the rules of
// another family. The branches of one family share a status. A family is
// `single` if it has one branch.
const FAMILIES = [
  {name: 'master', base: /^master$/, single: true},
  {name: 'release', base: /^release\/\d{8}$/},
];

// Time to wait after each status write. GitHub limits the rate of writes.
const WRITE_INTERVAL_MS = 1000;

// Maximum time between the read of the pull requests and the write of a
// successful status. The other writes of a run take time, and each account
// with write access can cause such writes. A pull request can change in that
// time.
const MAX_SUCCESS_DELAY_MS = 2 * 60 * 1000;

// Maximum number of pages of older reviews that are read for a pull request.
// Each page is one more query in each run, and each account can add reviews.
// Reviews that are not read can only add approvals.
const MAX_OLDER_REVIEW_PAGES = 2;

// Number of statuses of one family on a commit at which the script sets no
// successful status. GitHub refuses the statuses after the first 1000, and a
// successful status must not stay when it is out of date.
const MAX_STATUSES_FOR_SUCCESS = 500;

// The status of a commit that cannot be evaluated.
const ERROR_STATUS = {
  state: 'error',
  description: 'Cannot evaluate the maintainer approvals.',
};

// The status of a commit that has too many statuses.
const STATUS_LIMIT_STATUS = {
  state: 'error',
  description: 'Too many statuses on this commit. Push a new commit.',
};

// The part of a status description for a pull request whose author gives no
// agreement, because of the last change of the pull request.
const NOT_BY_AUTHOR =
    'another account last changed the base branch or the open or ready state';

// The status description of a draft pull request.
const DRAFT_DESCRIPTION = 'The pull request is a draft.';

// The status of a commit that is not the head commit of an open pull request
// of the family.
const NOT_NEEDED_STATUS = {
  state: 'pending',
  description: 'No open pull request needs this status.',
};

// Time after the last update of a closed or merged pull request in which the
// script reads that pull request.
const CLOSED_HORIZON_MS = 48 * 60 * 60 * 1000;

// Maximum number of pages of closed or merged pull requests that are read.
const MAX_CLOSED_PAGES = 10;

// Arguments of a `reviews` connection: a page of the newest reviews that can
// change the opinion of a reviewer.
const REVIEWS_ARGUMENTS =
    'last: 100, states: [APPROVED, CHANGES_REQUESTED, DISMISSED]';

// The fields of a page of reviews.
const REVIEW_FIELDS = `
  pageInfo { hasPreviousPage startCursor }
  nodes { state submittedAt commit { oid } author { ...id } }`;

// Selects the GitHub user ID of an account.
const ID_FRAGMENT = `
  fragment id on Actor {
    ... on User { databaseId }
    ... on Bot { databaseId }
  }`;

/**
 * Returns the name of the commit status of a family of base branches. The
 * branch rules require this status from the GitHub App that the workflow
 * authenticates as.
 *
 * @param {string} family - Name of the family.
 * @return {string} The status context.
 */
function statusContext(family) {
  return `maintainer-approval/${family}`;
}

// Selects the head commit of a pull request, and the newest status of each
// name on that commit. GitHub does not distinguish the case of the letters of
// a status name, and a lookup of one name finds a status only if the newest
// status of that name has the same letters. Thus, the script reads all names.
const HEAD_COMMIT = `
  commits(last: 1) {
    nodes {
      commit {
        oid
        status {
          contexts {
            context
            state
            description
            creator { __typename login }
          }
        }
      }
    }
  }`;

// Number of open pull requests in a page. A query for a larger page can take
// longer than the time limit of the API.
const PAGE_SIZE = 25;

// Reads the state of a page of the open pull requests.
const PULL_REQUESTS_QUERY = `
  query($owner: String!, $repo: String!, $cursor: String, $first: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequests(
          states: OPEN, first: $first, after: $cursor,
          orderBy: {field: CREATED_AT, direction: ASC}) {
        pageInfo { hasNextPage endCursor }
        nodes {
          number
          isDraft
          baseRefName
          headRefOid
          headRefName
          headRepository { nameWithOwner }
          author { ...id }
          baseChanges: timelineItems(
              itemTypes: [BASE_REF_CHANGED_EVENT, AUTOMATIC_BASE_CHANGE_SUCCEEDED_EVENT],
              last: 1) {
            nodes {
              ... on BaseRefChangedEvent { createdAt }
              ... on AutomaticBaseChangeSucceededEvent { createdAt }
            }
          }
          lastChange: timelineItems(
              itemTypes: [
                BASE_REF_CHANGED_EVENT, AUTOMATIC_BASE_CHANGE_SUCCEEDED_EVENT,
                REOPENED_EVENT, READY_FOR_REVIEW_EVENT
              ],
              last: 1) {
            nodes {
              ... on BaseRefChangedEvent { actor { ...id } }
              ... on ReopenedEvent { actor { ...id } }
              ... on ReadyForReviewEvent { actor { ...id } }
            }
          }
          reviews(${REVIEWS_ARGUMENTS}) {${REVIEW_FIELDS}}
          ${HEAD_COMMIT}
        }
      }
    }
  }${ID_FRAGMENT}`;

// Reads the reviews of a pull request that are older than a cursor.
const OLDER_REVIEWS_QUERY = `
  query($owner: String!, $repo: String!, $number: Int!, $cursor: String!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $number) {
        reviews(${REVIEWS_ARGUMENTS}, before: $cursor) {${REVIEW_FIELDS}}
      }
    }
  }${ID_FRAGMENT}`;

// Reads the head commits of a page of the closed or merged pull requests. The
// pull request with the newest update is first.
const CLOSED_PULL_REQUESTS_QUERY = `
  query($owner: String!, $repo: String!, $cursor: String) {
    repository(owner: $owner, name: $repo) {
      pullRequests(
          states: [CLOSED, MERGED], first: 50, after: $cursor,
          orderBy: {field: UPDATED_AT, direction: DESC}) {
        pageInfo { hasNextPage endCursor }
        nodes {
          updatedAt
          merged
          baseRefName
          headRefOid
          ${HEAD_COMMIT}
        }
      }
    }
  }`;

/**
 * Parses a YAML file with the yq binary in PATH.
 *
 * @param {string} file - Path of the YAML file.
 * @return {!Object} The parsed contents.
 */
function loadYAML(file) {
  return JSON.parse(execFileSync('yq', ['--output-format=json', '.', file], {
    encoding: 'utf8',
    // Do not give the credentials of the workflow step to yq.
    env: {PATH: process.env.PATH},
  }));
}

/**
 * Returns the GitHub user ID of a roster entry.
 *
 * @param {!Object} entry - An entry of maintainers.yaml or bots.yaml.
 * @return {number} The GitHub user ID.
 */
function userID(entry) {
  const id = entry?.github_id;
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new Error(`invalid github_id in ${JSON.stringify(entry)}`);
  }
  return id;
}

/**
 * Returns the entries of the active and hiatus maintainers. Emeritus
 * maintainers are excluded.
 *
 * @param {!Object} roster - The contents of governance/maintainers.yaml.
 * @return {!Array<!Object>} The entries.
 */
function countedMaintainers(roster) {
  return roster.maintainers.filter((m) => {
    const kind = String(m.status).split(':')[0];
    if (kind !== 'ACTIVE' && kind !== 'HIATUS_SINCE' &&
        kind !== 'EMERITUS_SINCE') {
      throw new Error(`invalid status in ${JSON.stringify(m)}`);
    }
    return kind !== 'EMERITUS_SINCE';
  });
}

/**
 * Returns the GitHub user IDs of the active and hiatus maintainers. Emeritus
 * maintainers are excluded.
 *
 * @param {!Object} roster - The contents of governance/maintainers.yaml.
 * @return {!Set<number>} The GitHub user IDs.
 */
function maintainerIDs(roster) {
  return new Set(countedMaintainers(roster).map(userID));
}

/**
 * Returns the GitHub user IDs of the trusted bots.
 *
 * @param {!Object} roster - The contents of governance/bots.yaml.
 * @return {!Set<number>} The GitHub user IDs.
 */
function botIDs(roster) {
  return new Set(roster.bots.map(userID));
}

/**
 * Returns the differences between the rosters and the GitHub accounts. The
 * script identifies an account by its ID, and a person who reads a roster
 * identifies it by its username. Thus, the username of an entry must be that
 * of the account with the ID. A maintainer must be a user, and a trusted bot
 * must be a bot. Emeritus maintainers are not examined.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {(function(string): !Object)=} load - Parses a YAML file. Defaults to
 *     loadYAML.
 * @return {!Promise<!Array<string>>} A description of each difference.
 */
async function rosterDifferences(github, load = loadYAML) {
  const workspace = process.env.GITHUB_WORKSPACE || '.';
  const maintainers = load(path.join(workspace, 'governance/maintainers.yaml'));
  const bots = load(path.join(workspace, 'governance/bots.yaml'));
  const entries = [
    ...countedMaintainers(maintainers).map((entry) => ({entry, type: 'User'})),
    ...bots.bots.map((entry) => ({entry, type: 'Bot'})),
  ];
  const differences = await Promise.all(entries.map(async ({entry, type}) => {
    const {data: account} = await github.request(
        'GET /user/{account_id}', {account_id: userID(entry)});
    if (typeof entry.github !== 'string' ||
        typeof account.login !== 'string' ||
        account.login.toLowerCase() !== entry.github.toLowerCase() ||
        account.type !== type) {
      return `${entry.github} (${entry.github_id}) must be a ${type}: the ` +
          `account with this ID is ${account.login}, a ${account.type}`;
    }
    return undefined;
  }));
  return differences.filter((difference) => difference !== undefined);
}

/**
 * Returns the GitHub user IDs of the reviewers who have an approval of the
 * pull request that is in effect.
 *
 * An approval is in effect if all of these are true:
 *   - It is not dismissed.
 *   - It is for the head commit.
 *   - It is newer than the last change of the base branch.
 *   - The reviewer has no newer review that changes the opinion of the
 *     reviewer, for example a request for changes or a dismissed review.
 *     Comments and pending reviews do not change it.
 *
 * If the rules of the base branch dismiss stale approvals, GitHub dismisses
 * an approval when the changes of the pull request become different. If they
 * stay the same, for example after a rebase, GitHub moves the approval to the
 * new head commit.
 *
 * @param {{
 *   headSHA: string,
 *   baseChangedAt: (string|undefined),
 *   reviews: !Array<!Object>,
 * }} pr
 *     headSHA: The head commit.
 *     baseChangedAt: Time of the last change of the base branch.
 *     reviews: The reviews, oldest first.
 * @return {!Set<number>} The GitHub user IDs.
 */
function approverIDs({headSHA, baseChangedAt, reviews}) {
  const ids = new Set();
  for (const review of reviews) {
    if (review.state === 'COMMENTED' || review.state === 'PENDING') {
      // Does not change the opinion of the reviewer.
      continue;
    }
    const id = review.author?.databaseId;
    if (review.state === 'APPROVED' && review.commit?.oid === headSHA &&
        (!baseChangedAt || review.submittedAt > baseChangedAt)) {
      ids.add(id);
    } else {
      ids.delete(id);
    }
  }
  // Reviews of deleted accounts have no author.
  ids.delete(undefined);
  return ids;
}

/**
 * Applies the approval rule to a pull request.
 *
 * A draft pull request is not successful: its author does not propose a merge.
 *
 * Each change needs two agreements. The author gives one if all of these are
 * true:
 *   - The author is a maintainer or a trusted bot.
 *   - The author pushed the head commit. That push is the agreement of the
 *     author to all content of the head commit.
 *   - No other account made the last change of the pull request that selects
 *     the base branch, opens the pull request again, or marks it as ready for
 *     review. Without this, another account can use the agreement of the
 *     author for a merge that the author did not propose.
 * Each other maintainer who approved the pull request gives one.
 *
 * @param {{
 *   author: (number|undefined),
 *   draft: (boolean|undefined),
 *   lastChangeByAuthor: boolean,
 *   pushedByAuthor: (boolean|undefined),
 *   approvers: !Set<number>,
 *   maintainers: !Set<number>,
 *   bots: !Set<number>,
 * }} params
 *     author: GitHub user ID of the pull request author.
 *     draft: Whether the pull request is a draft.
 *     lastChangeByAuthor: Whether no other account made the last change of
 *         the base branch, or of the open or ready state, of the pull request.
 *     pushedByAuthor: Whether the author pushed the head commit. If undefined,
 *         the state is as if the author did not.
 *     approvers: Reviewers who have an approval that is in effect.
 *     maintainers: The maintainers.
 *     bots: The trusted bots.
 * @return {{state: string, description: string, approvals: number}} The
 *     commit status, and the number of other maintainers who have an approval
 *     that is in effect.
 */
function evaluate({
  author,
  draft,
  lastChangeByAuthor,
  pushedByAuthor,
  approvers,
  maintainers,
  bots,
}) {
  let kind;
  if (maintainers.has(author)) {
    kind = 'maintainer';
  } else if (bots.has(author)) {
    kind = 'trusted bot';
  }
  let needed = 2;
  let needs = 'needs 2';
  if (kind && !lastChangeByAuthor) {
    needs = `needs 2 (${NOT_BY_AUTHOR})`;
  } else if (kind && pushedByAuthor) {
    needed = 1;
    needs = `needs 1 (the author is a ${kind})`;
  } else if (kind && pushedByAuthor === false) {
    needs = 'needs 2 (the author did not push the head commit)';
  } else if (kind) {
    needs = 'needs 1 (2 if the author did not push the head commit)';
  }
  let approvals = 0;
  for (const id of approvers) {
    if (id !== author && maintainers.has(id)) {
      approvals++;
    }
  }
  if (draft) {
    return {state: 'pending', description: DRAFT_DESCRIPTION, approvals};
  }
  return {
    state: approvals >= needed ? 'success' : 'pending',
    description: `Maintainer approvals: ${approvals}, ${needs}.`,
    approvals,
  };
}

/**
 * Returns the newest status of each family on the head commit of a pull
 * request.
 *
 * @param {!Object} node - A pull request of a query that has HEAD_COMMIT.
 * @param {string} appSlug - Slug of the GitHub App that sets the statuses.
 * @return {(!Object<string, {
 *   own: boolean,
 *   state: string,
 *   description: ?string,
 * }>|undefined)} The statuses by family name, or undefined if the query did
 *     not return the head commit. `own` is whether the app set the status
 *     with the exact name of the status of the family. A status that the app
 *     did not set, or that has other letter cases in its name, hides the
 *     status of the app.
 */
function headStatuses(node, appSlug) {
  const head = node.commits.nodes[0]?.commit;
  if (head?.oid !== node.headRefOid) {
    return undefined;
  }
  const statuses = {};
  for (const family of FAMILIES) {
    const name = statusContext(family.name);
    const status = (head.status?.contexts || [])
                       .find((s) => String(s.context).toLowerCase() === name);
    if (status) {
      statuses[family.name] = {
        own: status.context === name && status.creator?.__typename === 'Bot' &&
            status.creator.login === appSlug,
        state: status.state.toLowerCase(),
        description: status.description,
      };
    }
  }
  return statuses;
}

/**
 * Reads the pull requests of the repository.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {{owner: string, repo: string, appSlug: string, now: number}} params
 *     appSlug: Slug of the GitHub App that sets the statuses.
 *     now: The time, in milliseconds since the epoch.
 * @param {{fail: function(string), warn: function(string)}} report - Reports
 *     a failure or a warning.
 * @return {!Promise<{
 *   prs: !Array<!Object>,
 *   successes: !Array<{family: string, sha: string, own: boolean}>,
 *   incomplete: boolean,
 * }>}
 *     prs: The open pull requests whose base branch is in a family, oldest
 *         first. The `status` of a pull request is the status of its family
 *         that the app set on the head commit, if the response has one. If
 *         not `statusKnown`, the commit can have another status of the app. A
 *         pull request has a `readError` if not all of its data can be read.
 *     successes: The family and the commit of each status that is successful,
 *         or that the app did not set (it can hide a successful status of the
 *         app), on the head commits of the open pull requests, and of the
 *         closed or merged pull requests that readClosedPullRequests reads.
 *         A merged pull request keeps the status of the family of its base
 *         branch.
 *     incomplete: Whether an open pull request is absent from `prs` because it
 *         cannot be read.
 */
async function readPullRequests(
    github, {owner, repo, appSlug, now}, {fail, warn}) {
  const prs = [];
  const successes = [];
  let incomplete = false;
  const addSuccesses = (statuses, sha, kept) => {
    for (const [family, status] of Object.entries(statuses || {})) {
      if (family !== kept && (!status.own || status.state === 'success')) {
        successes.push({family, sha, own: status.own});
      }
    }
  };

  // Returns the reviews of a pull request, oldest first.
  const allReviews = async (node) => {
    let page = node.reviews;
    let reviews = page.nodes;
    for (let pages = 0; page.pageInfo.hasPreviousPage; pages++) {
      if (pages === MAX_OLDER_REVIEW_PAGES) {
        warn(`#${node.number}: only the newest ${reviews.length} reviews ` +
             'are read');
        break;
      }
      const older = await github.graphql(OLDER_REVIEWS_QUERY, {
        owner,
        repo,
        number: node.number,
        cursor: page.pageInfo.startCursor,
      });
      page = older.repository.pullRequest.reviews;
      reviews = [...page.nodes, ...reviews];
    }
    // The order of the submissions. The sort keeps the order of the response
    // for equal times.
    return reviews.toSorted(
        (a, b) => a.submittedAt < b.submittedAt ? -1 :
                  a.submittedAt > b.submittedAt ? 1 : 0);
  };

  let cursor = null;
  // The number of the last pull request that was read.
  let last = 0;
  // The size of the next page.
  let size = PAGE_SIZE;
  for (;;) {
    // The indexes of the pull requests of the page that have errors.
    const broken = new Set();
    let pageError;
    let repository;
    try {
      ({repository} = await github.graphql(
           PULL_REQUESTS_QUERY, {owner, repo, cursor, first: size}));
    } catch (error) {
      // A response with errors has the data that is available. Continue with
      // that data only if each error is in one pull request.
      const paths = (error.errors || [{}]).map(({path: at}) => at);
      if (paths.length === 0 ||
          !paths.every(
              (at) => at?.[0] === 'repository' && at[1] === 'pullRequests' &&
                  at[2] === 'nodes' && Number.isInteger(at[3]))) {
        if (size === 1) {
          throw error;
        }
        // The query for a page with many reviews can take longer than the
        // time limit of the API. Read a smaller page.
        size = Math.ceil(size / 2);
        warn(`reads a page of ${size} pull request(s) after a failure: ` +
             error.message);
        continue;
      }
      for (const at of paths) {
        broken.add(at[3]);
      }
      pageError = error;
      repository = error.data.repository;
      fail(`incomplete response: ${error.message}`);
    }
    size = PAGE_SIZE;
    for (const [index, node] of repository.pullRequests.nodes.entries()) {
      if (!node?.headRefOid || !node.baseRefName) {
        fail(`cannot read the pull request after #${last}`);
        incomplete = true;
        continue;
      }
      last = node.number;
      const family = FAMILIES.find((f) => f.base.test(node.baseRefName));
      const pr = {
        number: node.number,
        family: family?.name,
        base: node.baseRefName,
        headSHA: node.headRefOid,
      };
      let statuses;
      try {
        statuses = headStatuses(node, appSlug);
      } catch (error) {
        // The data has an error. The status is not known.
      }
      if (!statuses && !broken.has(index)) {
        fail(`#${node.number}: cannot read the status of the head commit`);
      }
      addSuccesses(statuses, node.headRefOid);
      const status = statuses?.[pr.family];
      pr.statusKnown = Boolean(statuses) && !broken.has(index) &&
          status?.own !== false;
      pr.status = status?.own ? status : undefined;
      try {
        if (broken.has(index)) {
          throw pageError;
        }
        if (typeof node.isDraft !== 'boolean') {
          throw new Error('cannot read the draft state');
        }
        pr.draft = node.isDraft;
        pr.author = node.author?.databaseId;
        pr.headRepository = node.headRepository?.nameWithOwner;
        pr.headRefName = node.headRefName;
        const [change] = node.baseChanges.nodes;
        if (node.baseChanges.nodes.length > 0 &&
            typeof change?.createdAt !== 'string') {
          throw new Error('cannot read the change of the base branch');
        }
        pr.baseChangedAt = change?.createdAt;
        // A change of the base branch that GitHub makes, when the base branch
        // is deleted after a merge, has no actor.
        const [lastChange] = node.lastChange.nodes;
        pr.lastChangeByAuthor = node.lastChange.nodes.length === 0 ||
            (pr.author !== undefined &&
             lastChange?.actor?.databaseId === pr.author);
        if (family) {
          pr.reviews = await allReviews(node);
        }
      } catch (error) {
        pr.readError = error;
      }
      if (family) {
        prs.push(pr);
      }
    }
    const {hasNextPage, endCursor} = repository.pullRequests.pageInfo;
    if (!hasNextPage) {
      break;
    }
    cursor = endCursor;
  }

  try {
    const closed = await readClosedPullRequests(github, {owner, repo, now}, warn);
    for (const node of closed) {
      const kept = node.merged === true ?
          FAMILIES.find((f) => f.base.test(node.baseRefName)) :
          undefined;
      addSuccesses(headStatuses(node, appSlug), node.headRefOid, kept?.name);
    }
  } catch (error) {
    fail(`cannot read the closed pull requests: ${error.message}`);
  }
  return {prs, successes, incomplete};
}

/**
 * Reads the closed or merged pull requests whose last update is not older
 * than CLOSED_HORIZON_MS, and at least the 50 with the newest updates. It
 * reads no more than MAX_CLOSED_PAGES pages. Below that limit, an update of
 * other pull requests does not remove a pull request from this set before
 * that time.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {{owner: string, repo: string, now: number}} params
 *     now: The time, in milliseconds since the epoch.
 * @param {function(string)} warn - Reports a warning.
 * @return {!Promise<!Array<!Object>>} The pull requests of
 *     CLOSED_PULL_REQUESTS_QUERY.
 */
async function readClosedPullRequests(github, {owner, repo, now}, warn) {
  const horizon = now - CLOSED_HORIZON_MS;
  // A time that cannot be read is not old.
  const isOld = (node) => Date.parse(node.updatedAt) < horizon;
  const closed = [];
  let cursor = null;
  for (let pages = 0;; pages++) {
    if (pages === MAX_CLOSED_PAGES) {
      warn(`only the ${closed.length} closed pull requests with the newest ` +
           'updates are read');
      break;
    }
    const {repository} = await github.graphql(
        CLOSED_PULL_REQUESTS_QUERY, {owner, repo, cursor});
    const {nodes, pageInfo} = repository.pullRequests;
    closed.push(...(pages === 0 ? nodes : nodes.filter((n) => !isOld(n))));
    if (!pageInfo.hasNextPage || nodes.length === 0 || isOld(nodes.at(-1))) {
      break;
    }
    cursor = pageInfo.endCursor;
  }
  return closed;
}

/**
 * Returns the GitHub user ID of the account that pushed the head commit of a
 * pull request to its branch.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {!Object} pr - A pull request from readPullRequests.
 * @return {!Promise<(number|undefined)>} The GitHub user ID. It is undefined
 *     if the head repository does not exist, if the newest activity of the
 *     branch did not result in the head commit, or if that activity has no
 *     actor.
 */
async function headPusher(github, pr) {
  if (!pr.headRepository) {
    return undefined;
  }
  const [owner, repo] = pr.headRepository.split('/');
  const {data} = await github.request('GET /repos/{owner}/{repo}/activity', {
    owner,
    repo,
    ref: `refs/heads/${pr.headRefName}`,
    per_page: 1,
  });
  return data[0]?.after === pr.headSHA ? data[0].actor?.id : undefined;
}

/**
 * Examines the rules of a branch.
 *
 * The script needs these rules:
 *   - Dismiss the approvals of a pull request when its changes become
 *     different. Without that, an approval can be for other changes than those
 *     of the head commit.
 *   - Require one approval, and require the approval of the most recent push.
 *     A status changes some time after the pull request does. In that time,
 *     a merge still needs an approval from an account that did not make the
 *     most recent push.
 *   - If the rules require the status of the family, they require it from the
 *     app only. A status from another source is not a result of the script.
 *   - The rules do not require the status of another family: the script does
 *     not set that status for the pull requests to this branch.
 *
 * Each rule can be in a different ruleset. The response does not have the
 * classic branch protection rules, thus they do not count.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {{
 *   owner: string,
 *   repo: string,
 *   branch: string,
 *   family: string,
 *   appID: number,
 * }} params
 *     branch: The branch.
 *     family: Name of the family of the branch.
 *     appID: ID of the GitHub App that sets the statuses.
 * @return {!Promise<{missing: !Array<string>, enforced: boolean}>}
 *     missing: A description of each rule that the script needs and that the
 *         branch does not have.
 *     enforced: Whether the rules require the status of the family, or two
 *         approvals. If not, a pull request can merge with the approval of
 *         one account.
 */
async function examineRules(github, {owner, repo, branch, family, appID}) {
  const {data: rules} = await github.request(
      'GET /repos/{owner}/{repo}/rules/branches/{branch}',
      {owner, repo, branch, per_page: 100});
  if (rules.length >= 100) {
    // The response can be one page of more rules.
    throw new Error('too many rules');
  }
  const parameters = rules.filter((rule) => rule.type === 'pull_request')
                         .map((rule) => rule.parameters || {});
  const counts = parameters.map((p) => p.required_approving_review_count)
                     .filter((count) => Number.isInteger(count));
  const missing = [];
  if (!parameters.some((p) => p.dismiss_stale_reviews_on_push === true)) {
    missing.push('dismiss stale approvals');
  }
  if (!counts.some((count) => count >= 1)) {
    missing.push('require one approval');
  }
  if (!parameters.some((p) => p.require_last_push_approval === true)) {
    missing.push('require the approval of the most recent push');
  }
  // The statuses of this workflow that the rules require. GitHub does not
  // distinguish the case of the letters of a status name.
  const required =
      rules.filter((rule) => rule.type === 'required_status_checks')
          .flatMap((rule) => rule.parameters?.required_status_checks || [])
          .map((check) => ({
                 context: String(check.context).toLowerCase(),
                 source: check.integration_id,
               }));
  const own = required.filter((c) => c.context === statusContext(family));
  if (own.some((c) => c.source !== appID)) {
    missing.push(`require ${statusContext(family)} from the app only`);
  }
  for (const other of FAMILIES) {
    if (other.name !== family &&
        required.some((c) => c.context === statusContext(other.name))) {
      missing.push(`do not require ${statusContext(other.name)}`);
    }
  }
  return {
    missing,
    enforced: own.length > 0 || counts.some((count) => count >= 2),
  };
}

/**
 * Returns whether a commit has too many statuses of a family for a new
 * successful status. With too many statuses, GitHub can refuse the status that
 * replaces the successful one when it is out of date.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {{owner: string, repo: string, sha: string, family: string}} params
 * @return {!Promise<boolean>} Whether the commit has too many statuses.
 */
async function tooManyStatuses(github, {owner, repo, sha, family}) {
  let count = 0;
  // 10 pages have the first 1000 statuses of all contexts.
  for (let page = 1; page <= 10; page++) {
    const {data} = await github.request(
        'GET /repos/{owner}/{repo}/commits/{ref}/statuses',
        {owner, repo, ref: sha, per_page: 100, page});
    // GitHub does not distinguish the case of the letters of a status name.
    count += data.filter(
        (s) => String(s.context).toLowerCase() === statusContext(family))
                 .length;
    if (count >= MAX_STATUSES_FOR_SUCCESS) {
      return true;
    }
    if (data.length < 100) {
      return false;
    }
  }
  // The commit can have more statuses than the pages show.
  return true;
}

/**
 * Returns the status of a commit for a family of base branches.
 *
 * For each base branch, one of the pull requests must be successful. A second
 * pull request with the same commit and the same base branch has the same
 * changes, thus it needs no approvals of its own. If no pull request of a
 * base branch is successful, the status is that of the pull request with the
 * most approvals.
 *
 * @param {!Object} github - An authenticated Octokit client.
 * @param {!Array<!Object>} prs - The open pull requests with this head commit
 *     whose base branch is in the family.
 * @param {!Set<number>} maintainers - The maintainers.
 * @param {!Set<number>} bots - The trusted bots.
 * @param {function(string)} fail - Reports a failure.
 * @return {!Promise<{
 *   state: string,
 *   description: string,
 *   approvals: (number|undefined),
 * }>} The commit status. `approvals` is the largest number of maintainer
 *     approvals in effect of one of the pull requests, if the pull request of
 *     the status can be evaluated.
 */
async function commitStatus(github, prs, maintainers, bots, fail) {
  // The result for each base branch.
  const bases = new Map();
  // The description names the pull request only if that is necessary: the
  // other pull requests of a base branch must not change the description.
  const severalBases = new Set(prs.map((pr) => pr.base)).size > 1;
  let mostApprovals = 0;
  for (const pr of prs) {
    let result;
    try {
      if (pr.readError) {
        throw pr.readError;
      }
      const rule = {
        author: pr.author,
        draft: pr.draft,
        lastChangeByAuthor: pr.lastChangeByAuthor,
        approvers: approverIDs(pr),
        maintainers,
        bots,
      };
      // Read the pusher only if it decides the result.
      result = evaluate(rule);
      if (result.state !== 'success' &&
          evaluate({...rule, pushedByAuthor: true}).state === 'success') {
        const pusher = await headPusher(github, pr);
        result = evaluate({
          ...rule,
          pushedByAuthor: pusher !== undefined && pusher === pr.author,
        });
      }
    } catch (error) {
      fail(`#${pr.number}: cannot evaluate: ${error.message}`);
      result = {...ERROR_STATUS};
    }
    if (severalBases) {
      result.description = `#${pr.number}: ${result.description}`;
    }
    mostApprovals = Math.max(mostApprovals, result.approvals || 0);
    const best = bases.get(pr.base);
    if (!best ||
        (best.state !== 'success' &&
         (result.state === 'success' ||
          (result.approvals || 0) > (best.approvals || 0)))) {
      bases.set(pr.base, result);
    }
  }
  const results = [...bases.values()];
  const result =
      results.find((r) => r.state !== 'success') || results[0];
  if (result.approvals !== undefined) {
    result.approvals = mostApprovals;
  }
  return result;
}

/**
 * Sets the maintainer approval status on the head commit of each open pull
 * request to a branch of a family, if that status is out of date. A commit
 * gets its first status when the status is successful, when a maintainer
 * approval is in effect, or when the script cannot read the statuses of the
 * commit. While it cannot read them, each run sets a status on that commit.
 *
 * Also sets a pending status in place of a status that is successful, or that
 * the app did not set (such a status can hide a successful one), if no open
 * pull request to a branch of that family has that head commit. This applies
 * to the head commits of the open pull requests, and of the closed or merged
 * pull requests that readClosedPullRequests reads. A merged pull request
 * keeps the status of the family of its base branch.
 *
 * Also reports the differences between the rosters and the GitHub accounts,
 * and the base branches whose rules do not use the statuses. These reports do
 * not change a status.
 *
 * The event that started the workflow is not an input.
 *
 * @param {{
 *   github: !Object,
 *   context: !Object,
 *   core: !Object,
 *   appSlug: string,
 *   appID: number,
 *   load: ((function(string): !Object)|undefined),
 *   sleep: ((function(number): !Promise)|undefined),
 *   now: ((function(): number)|undefined),
 * }} params - The injected actions/github-script objects, and the options of
 *     the script.
 *     github: An authenticated Octokit client.
 *     context: The GitHub Actions workflow context.
 *     core: The GitHub Actions core toolkit for logging/errors.
 *     appSlug: Slug of the GitHub App that `github` authenticates as.
 *     appID: ID of that app. The script cannot read it from GitHub with the
 *         token of the app.
 *     load: Parses a YAML file. Defaults to loadYAML.
 *     sleep: Waits for a number of milliseconds. Defaults to a timer.
 *     now: Returns the time, in milliseconds since the epoch. Defaults to the
 *         clock.
 * @return {!Promise<{commits: number, written: number}>} The number of pairs
 *     of a family and a head commit that the script examined, and the number
 *     of statuses that it set.
 */
module.exports = async ({
  github,
  context,
  core,
  appSlug,
  appID,
  load = loadYAML,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = Date.now,
}) => {
  if (!appSlug) {
    throw new Error('the slug of the GitHub App is not set');
  }
  if (!Number.isSafeInteger(appID) || appID <= 0) {
    throw new Error('the ID of the GitHub App is not set');
  }
  const {owner, repo} = context.repo;
  const targetURL =
      `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  let failures = 0;
  const fail = (message) => {
    failures++;
    core.error(message);
  };
  const warn = (message) => core.warning(message);

  const {prs: open, successes, incomplete} =
      await readPullRequests(
          github, {owner, repo, appSlug, now: now()}, {fail, warn});
  const readAt = now();
  // The pull requests of each family and head commit.
  const commits = new Map();
  for (const pr of open) {
    const key = `${pr.family} ${pr.headSHA}`;
    if (!commits.has(key)) {
      commits.set(key, []);
    }
    commits.get(key).push(pr);
  }

  let maintainers;
  let bots;
  let rosterError;
  try {
    const workspace = process.env.GITHUB_WORKSPACE || '.';
    maintainers =
        maintainerIDs(load(path.join(workspace, 'governance/maintainers.yaml')));
    bots = botIDs(load(path.join(workspace, 'governance/bots.yaml')));
  } catch (error) {
    rosterError = error;
    fail(`cannot read the rosters: ${error.message}`);
  }

  // The base branches whose rules do not let the script count approvals.
  const unverified = new Set();
  // The base branches whose rules cannot be read. They get no new successful
  // status. The statuses that they have stay as they are while they are
  // correct: the rules were sufficient when the script set them.
  const unread = new Set();
  for (const branch of new Set(open.map((pr) => pr.base))) {
    try {
      const family = FAMILIES.find((f) => f.base.test(branch)).name;
      const {missing, enforced} =
          await examineRules(github, {owner, repo, branch, family, appID});
      if (missing.length > 0) {
        unverified.add(branch);
        fail(`no ruleset of ${branch} has these rules: ` +
             missing.join(', '));
      } else if (!enforced) {
        // The statuses are set, but the rules do not use them.
        fail(`the rules of ${branch} do not require ${statusContext(family)}` +
             ', and they do not require two approvals');
      }
    } catch (error) {
      unread.add(branch);
      fail(`cannot read the rules of ${branch}: ${error.message}`);
    }
  }

  // A write can fail. Thus, the writes are in this order:
  //   Rank 0: Replace the successful statuses of the app that are out of
  //           date.
  //   Rank 1: Replace the statuses whose state is not known, if the new state
  //           is not successful. Each account with write access can cause
  //           these writes, thus they come after rank 0.
  //   Rank 2: Set the new successful statuses.
  //   Rank 3: Set the other statuses.
  // In each rank, the newest pull request is first. The statuses that no
  // pull request needs are last in their rank.
  const writes = [];
  for (const prs of commits.values()) {
    const {family, headSHA: sha, status: current, statusKnown} = prs[0];
    let result;
    if (!rosterError && !prs.some((pr) => unverified.has(pr.base))) {
      result = await commitStatus(github, prs, maintainers, bots, fail);
      if (result.state === 'success' &&
          prs.some((pr) => unread.has(pr.base))) {
        continue;
      }
    } else if (!statusKnown || current?.state === 'success') {
      // Do not keep a successful status without the rosters, or without the
      // rules that make the approvals valid.
      result = {...ERROR_STATUS};
    } else {
      continue;
    }
    const isCurrent = () => current?.state === result.state &&
        current.description === result.description;
    if (isCurrent()) {
      continue;
    }
    if (result.state === 'success') {
      try {
        if (await tooManyStatuses(github, {owner, repo, sha, family})) {
          result = {...STATUS_LIMIT_STATUS, approvals: result.approvals};
        }
      } catch (error) {
        fail(`${sha}: cannot count the statuses: ${error.message}`);
        if (current?.state === 'success') {
          // The commit keeps the status, which has the correct state.
          continue;
        }
        result = {...ERROR_STATUS};
      }
    }
    if (result.state !== 'success' && statusKnown &&
        (isCurrent() || (!current && !(result.approvals > 0)))) {
      // The branch rules do not accept a commit without the status. Thus, a
      // commit without a status of the app gets a status that is not
      // successful only if a maintainer approval is in effect: the status
      // tells why the approval is not sufficient. An error status that is
      // already on the commit is not set again.
      continue;
    }
    let rank = 3;
    if (current?.state === 'success') {
      rank = 0;
    } else if (!statusKnown && result.state !== 'success') {
      rank = 1;
    } else if (result.state === 'success') {
      if (incomplete && !FAMILIES.find((f) => f.name === family).single) {
        // A pull request that cannot be read can have this head commit and
        // another base branch of the family.
        continue;
      }
      rank = 2;
    }
    writes.push({
      family,
      sha,
      result: {state: result.state, description: result.description},
      rank,
      number: prs.at(-1).number,
    });
  }
  // A pull request that cannot be read can need one of these statuses.
  const replaced = new Set();
  for (const {family, sha, own} of incomplete ? [] : successes) {
    const key = `${family} ${sha}`;
    if (commits.has(key) || replaced.has(key)) {
      continue;
    }
    replaced.add(key);
    writes.push({
      family,
      sha,
      result: NOT_NEEDED_STATUS,
      // A status of the app is successful. A status that the app did not set
      // has a state that is not known.
      rank: own ? 0 : 1,
      number: 0,
    });
  }
  writes.sort((a, b) => a.rank - b.rank || b.number - a.number);

  let written = 0;
  let refused = false;
  for (const {family, sha, result} of writes) {
    if (result.state === 'success') {
      if (now() - readAt > MAX_SUCCESS_DELAY_MS) {
        // The next run sets the status with new data.
        warn(`${sha} ${family}: the data is too old for a successful status`);
        continue;
      }
      // Other writes of this run took time, and the commit can have more
      // statuses now.
      try {
        if (await tooManyStatuses(github, {owner, repo, sha, family})) {
          fail(`${sha} ${family}: too many statuses for a successful status`);
          continue;
        }
      } catch (error) {
        fail(`${sha}: cannot count the statuses: ${error.message}`);
        continue;
      }
    }
    try {
      await github.rest.repos.createCommitStatus({
        owner,
        repo,
        sha,
        context: statusContext(family),
        target_url: targetURL,
        ...result,
      });
      written++;
      core.info(`${sha} ${family}: ${result.state}: ${result.description}`);
    } catch (error) {
      fail(`${sha} ${family}: cannot set the status: ${error.message}`);
      if (error.status === 403 || error.status === 429) {
        // GitHub refuses writes for some time. The next run continues.
        refused = true;
        break;
      }
    }
    await sleep(WRITE_INTERVAL_MS);
  }
  if (!rosterError && !refused) {
    // This does not change the result of a pull request.
    try {
      for (const difference of await rosterDifferences(github, load)) {
        fail(`roster: ${difference}`);
      }
    } catch (error) {
      fail(`cannot compare the rosters with the accounts: ${error.message}`);
    }
  }
  core.info(`Examined ${commits.size} pair(s) of a family and a head ` +
            `commit. Set ${written} of ${writes.length} status(es) that are ` +
            'out of date.');
  if (failures > 0) {
    core.setFailed(`${failures} failure(s)`);
  }
  return {commits: commits.size, written};
};

module.exports.approverIDs = approverIDs;
module.exports.botIDs = botIDs;
module.exports.evaluate = evaluate;
module.exports.loadYAML = loadYAML;
module.exports.maintainerIDs = maintainerIDs;
module.exports.rosterDifferences = rosterDifferences;
module.exports.statusContext = statusContext;
