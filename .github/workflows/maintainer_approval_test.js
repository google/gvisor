// Run with: node --test .github/workflows/maintainer_approval_test.js
// The tests that read the files of the repository need the yq binary.

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {test} = require('node:test');

const maintainerApproval = require('./maintainer_approval.js');
const {approverIDs, botIDs, evaluate, loadYAML, maintainerIDs, statusContext} =
    maintainerApproval;

const REPO_ROOT = path.join(__dirname, '..', '..');
const APP_SLUG = 'approval-app';
const APP_ID = 4242;
const MASTER = 'maintainer-approval/master';
const RELEASE = 'maintainer-approval/release';
const HEAD = 'a'.repeat(40);
const OTHER = 'b'.repeat(40);

// GitHub user IDs of the test accounts.
const ACTIVE1 = 1;
const ACTIVE2 = 2;
const HIATUS = 3;
const EMERITUS = 4;
const BOT = 5;
const OUTSIDER1 = 6;
const OUTSIDER2 = 7;

const ROSTERS = {
  'governance/maintainers.yaml': {
    maintainers: [
      {github: 'active1', github_id: ACTIVE1, status: 'ACTIVE'},
      {github: 'active2', github_id: ACTIVE2, status: 'ACTIVE'},
      {github: 'hiatus', github_id: HIATUS, status: 'HIATUS_SINCE:2026-01-02'},
      {
        github: 'emeritus',
        github_id: EMERITUS,
        status: 'EMERITUS_SINCE:2026-01-02',
      },
    ],
  },
  'governance/bots.yaml': {bots: [{github: 'bot', github_id: BOT}]},
};
const MAINTAINERS = maintainerIDs(ROSTERS['governance/maintainers.yaml']);
const BOTS = botIDs(ROSTERS['governance/bots.yaml']);

// A change of the base branch that GitHub makes.
const AUTOMATIC = Symbol('automatic');

// The time of the fake, and a time before it.
const NOW = Date.parse('2026-06-01T00:00:00Z');
const HOUR_MS = 60 * 60 * 1000;
function hoursAgo(hours) {
  return new Date(NOW - hours * HOUR_MS).toISOString();
}

// The reasons in the status descriptions, the other descriptions, and a
// function that makes a description.
const MAINTAINER = 'the author is a maintainer';
const TRUSTED_BOT = 'the author is a trusted bot';
const NOT_PUSHER = 'the author did not push the head commit';
const UNKNOWN_PUSHER = '2 if the author did not push the head commit';
const NOT_BY_AUTHOR =
    'another account last changed the base branch or the open or ready state';
const DRAFT = 'The pull request is a draft.';
const TOO_MANY = 'Too many statuses on this commit. Push a new commit.';
const ERROR = 'Cannot evaluate the maintainer approvals.';
const NOT_NEEDED = 'No open pull request needs this status.';
function description(approvals, needs, reason) {
  return `Maintainer approvals: ${approvals}, needs ${needs}` +
      (reason ? ` (${reason}).` : '.');
}

// A review as the GraphQL API returns it. Without `commit`, the fake uses the
// head commit of the pull request.
function review(id, state, at = '2026-02-01T00:00:00Z', commit = undefined) {
  return {
    author: id === null ? null : {databaseId: id},
    state,
    submittedAt: state === 'PENDING' ? null : at,
    commit,
  };
}

function approvals(...ids) {
  return ids.map((id) => review(id, 'APPROVED'));
}

test('statusContext', () => {
  // The branch rules require these names.
  assert.equal(statusContext('master'), MASTER);
  assert.equal(statusContext('release'), RELEASE);
});

test('maintainerIDs keeps active and hiatus maintainers', () => {
  assert.deepEqual([...MAINTAINERS].sort(), [ACTIVE1, ACTIVE2, HIATUS]);
});

test('maintainerIDs rejects invalid rosters', () => {
  const invalid = [
    {},
    {maintainers: [{github: 'a', github_id: 1}]},
    {maintainers: [{github: 'a', github_id: 1, status: 'RETIRED'}]},
    {maintainers: [{github: 'a', github_id: 1, status: 'active'}]},
    {maintainers: [{github: 'a', status: 'ACTIVE'}]},
    {maintainers: [{github: 'a', github_id: '1', status: 'ACTIVE'}]},
    {maintainers: [{github: 'a', github_id: 0, status: 'ACTIVE'}]},
    {maintainers: [{github: 'a', github_id: 1.5, status: 'ACTIVE'}]},
    {maintainers: [{github: 'a', github_id: 2 ** 60, status: 'ACTIVE'}]},
    {maintainers: [{github: 'a', status: 'HIATUS_SINCE:2026-01-02'}]},
  ];
  for (const roster of invalid) {
    assert.throws(() => maintainerIDs(roster), JSON.stringify(roster));
  }
});

test('maintainerIDs does not need the user ID of emeritus maintainers', () => {
  const roster = {maintainers: [{status: 'EMERITUS_SINCE:2026-01-02'}]};
  assert.equal(maintainerIDs(roster).size, 0);
});

test('botIDs', () => {
  assert.deepEqual([...BOTS], [BOT]);
  assert.equal(botIDs({bots: []}).size, 0);
  for (const roster of [{}, {bots: [{github: 'a'}]}, {bots: [{github_id: -1}]}]) {
    assert.throws(() => botIDs(roster), JSON.stringify(roster));
  }
});

test('approverIDs', () => {
  const baseChangedAt = '2026-02-02T00:00:00Z';
  const before = '2026-02-01T00:00:00Z';
  const after = '2026-02-03T00:00:00Z';
  const cases = [
    {name: 'no reviews', reviews: [], want: []},
    {name: 'approval', reviews: [review(1, 'APPROVED')], want: [1]},
    {
      name: 'two approvals of a reviewer',
      reviews: [review(1, 'APPROVED'), review(1, 'APPROVED')],
      want: [1],
    },
    {
      name: 'comment after an approval',
      reviews: [review(1, 'APPROVED'), review(1, 'COMMENTED')],
      want: [1],
    },
    {
      name: 'pending review after an approval',
      reviews: [review(1, 'APPROVED'), review(1, 'PENDING')],
      want: [1],
    },
    {name: 'comment only', reviews: [review(1, 'COMMENTED')], want: []},
    {
      name: 'changes requested after an approval',
      reviews: [review(1, 'APPROVED'), review(1, 'CHANGES_REQUESTED')],
      want: [],
    },
    {
      name: 'approval after changes requested',
      reviews: [review(1, 'CHANGES_REQUESTED'), review(1, 'APPROVED')],
      want: [1],
    },
    {name: 'dismissed approval', reviews: [review(1, 'DISMISSED')], want: []},
    {
      name: 'dismissed review after an approval',
      reviews: [review(1, 'APPROVED'), review(1, 'DISMISSED')],
      want: [],
    },
    {
      name: 'approval after a dismissed approval',
      reviews: [review(1, 'DISMISSED'), review(1, 'APPROVED')],
      want: [1],
    },
    {
      name: 'unknown state after an approval',
      reviews: [review(1, 'APPROVED'), review(1, 'NEW_STATE')],
      want: [],
    },
    {
      name: 'reviewers are independent',
      reviews: [
        review(1, 'APPROVED'),
        review(2, 'CHANGES_REQUESTED'),
        review(3, 'APPROVED'),
        review(2, 'COMMENTED'),
      ],
      want: [1, 3],
    },
    {
      name: 'deleted account',
      reviews: [review(null, 'APPROVED'), review(1, 'APPROVED')],
      want: [1],
    },
    {
      name: 'approval before a base change',
      baseChangedAt,
      reviews: [review(1, 'APPROVED', before)],
      want: [],
    },
    {
      name: 'approval at the time of a base change',
      baseChangedAt,
      reviews: [review(1, 'APPROVED', baseChangedAt)],
      want: [],
    },
    {
      name: 'approval after a base change',
      baseChangedAt,
      reviews: [review(1, 'APPROVED', after)],
      want: [1],
    },
    {
      name: 'approvals before and after a base change',
      baseChangedAt,
      reviews: [review(1, 'APPROVED', before), review(2, 'APPROVED', after)],
      want: [2],
    },
    {
      name: 'approval without a time after a base change',
      baseChangedAt,
      reviews: [{...review(1, 'APPROVED'), submittedAt: null}],
      want: [],
    },
  ];
  const at = '2026-02-01T00:00:00Z';
  const onHeadCommit = review(1, 'APPROVED', at, {oid: HEAD});
  const onOtherCommit = review(1, 'APPROVED', at, {oid: OTHER});
  cases.push(
      {name: 'approval of another commit', reviews: [onOtherCommit], want: []},
      {
        name: 'approval without a commit',
        reviews: [review(1, 'APPROVED', at, null)],
        want: [],
      },
      {
        name: 'approval of another commit after an approval',
        reviews: [onHeadCommit, onOtherCommit],
        want: [],
      },
      {
        name: 'approval after an approval of another commit',
        reviews: [onOtherCommit, onHeadCommit],
        want: [1],
      },
      {
        name: 'dismissed review after an approval of another commit',
        reviews: [onOtherCommit, review(1, 'DISMISSED')],
        want: [],
      });
  for (const c of cases) {
    const reviews = c.reviews.map(
        (r) => r.commit === undefined ? {...r, commit: {oid: HEAD}} : r);
    const got =
        approverIDs({headSHA: HEAD, baseChangedAt: c.baseChangedAt, reviews});
    assert.deepEqual([...got].sort(), c.want, c.name);
  }
});

test('evaluate', () => {
  // [author, pushedByAuthor, approvers, state, description]
  const cases = [
    // Author who is not a maintainer. The pusher does not change the rule.
    [OUTSIDER1, undefined, [], 'pending', description(0, 2)],
    [OUTSIDER1, undefined, [ACTIVE1], 'pending', description(1, 2)],
    [OUTSIDER1, undefined, [ACTIVE1, ACTIVE2], 'success', description(2, 2)],
    [OUTSIDER1, undefined, [ACTIVE1, ACTIVE2, HIATUS], 'success', description(3, 2)],
    [OUTSIDER1, undefined, [ACTIVE1, HIATUS], 'success', description(2, 2)],
    [OUTSIDER1, true, [ACTIVE1], 'pending', description(1, 2)],
    [OUTSIDER1, false, [ACTIVE1, ACTIVE2], 'success', description(2, 2)],
    // Only maintainers count.
    [
      OUTSIDER1, true, [ACTIVE1, OUTSIDER2, EMERITUS, BOT], 'pending',
      description(1, 2),
    ],
    // The author does not count as an approver.
    [OUTSIDER1, true, [OUTSIDER1, ACTIVE1], 'pending', description(1, 2)],
    // An author without an account is not a maintainer.
    [undefined, true, [ACTIVE1], 'pending', description(1, 2)],
    [undefined, undefined, [ACTIVE1, ACTIVE2], 'success', description(2, 2)],
    // An emeritus maintainer is not a maintainer.
    [EMERITUS, true, [ACTIVE1], 'pending', description(1, 2)],
    [EMERITUS, true, [ACTIVE1, ACTIVE2], 'success', description(2, 2)],
    // Author who is a maintainer and who pushed the head commit.
    [ACTIVE1, true, [], 'pending', description(0, 1, MAINTAINER)],
    [ACTIVE1, true, [ACTIVE1], 'pending', description(0, 1, MAINTAINER)],
    [ACTIVE1, true, [OUTSIDER1, EMERITUS], 'pending', description(0, 1, MAINTAINER)],
    [ACTIVE1, true, [ACTIVE2], 'success', description(1, 1, MAINTAINER)],
    [HIATUS, true, [ACTIVE1], 'success', description(1, 1, MAINTAINER)],
    [ACTIVE1, true, [HIATUS], 'success', description(1, 1, MAINTAINER)],
    // Author who is a maintainer and who did not push the head commit.
    [ACTIVE1, false, [], 'pending', description(0, 2, NOT_PUSHER)],
    [ACTIVE1, false, [ACTIVE2], 'pending', description(1, 2, NOT_PUSHER)],
    [ACTIVE1, false, [ACTIVE1, ACTIVE2], 'pending', description(1, 2, NOT_PUSHER)],
    [ACTIVE1, false, [ACTIVE2, HIATUS], 'success', description(2, 2, NOT_PUSHER)],
    // Author who is a maintainer, with a pusher that is not known. The state
    // is as if the author did not push the head commit.
    [ACTIVE1, undefined, [], 'pending', description(0, 1, UNKNOWN_PUSHER)],
    [ACTIVE1, undefined, [ACTIVE2], 'pending', description(1, 1, UNKNOWN_PUSHER)],
    [ACTIVE1, undefined, [ACTIVE2, HIATUS], 'success', description(2, 1, UNKNOWN_PUSHER)],
    // Author who is a trusted bot.
    [BOT, true, [], 'pending', description(0, 1, TRUSTED_BOT)],
    [BOT, true, [OUTSIDER1, EMERITUS], 'pending', description(0, 1, TRUSTED_BOT)],
    [BOT, true, [ACTIVE1], 'success', description(1, 1, TRUSTED_BOT)],
    [BOT, false, [ACTIVE1], 'pending', description(1, 2, NOT_PUSHER)],
    [BOT, false, [ACTIVE1, ACTIVE2], 'success', description(2, 2, NOT_PUSHER)],
    [BOT, undefined, [ACTIVE1], 'pending', description(1, 1, UNKNOWN_PUSHER)],
  ];
  for (const c of cases) {
    const [author, pushedByAuthor, approvers, state, want] = c;
    const rule = {
      author,
      lastChangeByAuthor: true,
      pushedByAuthor,
      approvers: new Set(approvers),
      maintainers: MAINTAINERS,
      bots: BOTS,
    };
    const got = evaluate(rule);
    // The number of approvals is the number in the description.
    const wantApprovals = Number(want.match(/^Maintainer approvals: (\d+),/)[1]);
    assert.deepEqual(
        got, {state, description: want, approvals: wantApprovals},
        JSON.stringify(c));
    // GitHub rejects a longer description.
    assert.ok(`#1234567: ${got.description}`.length <= 140);
    // A pull request is not a draft by default.
    for (const draft of [false, undefined]) {
      assert.deepEqual(evaluate({...rule, draft}), got, JSON.stringify(c));
    }
    // A draft is not successful.
    assert.deepEqual(
        evaluate({...rule, draft: true}),
        {state: 'pending', description: DRAFT, approvals: wantApprovals},
        JSON.stringify(c));
  }
});

// A pull request for the fake. The fake returns the newest items of `reviews`,
// `commits`, `baseChanges` and `lastChanges`, as the queries request.
//   status: The newest status of each context on the head commit. By default,
//       the commit has STALE_STATUS, thus each result is a status write. Null
//       for a commit without a status.
//   commits: The commits, oldest first. Each one is {oid, status}. Empty for a
//       pull request without commits.
//   baseChanges: Times of the changes of the base branch, oldest first.
//   updatedAt: Time of the last update of a closed pull request.
//   merged: Whether a closed pull request is merged.
//   lastChanges: The accounts that changed the base branch, or the open or
//       ready state, oldest first. Null for a deleted account, and AUTOMATIC
//       for a change of the base branch that GitHub makes.
function pullRequest(number, author, {
  sha = HEAD,
  base = 'master',
  reviews = [],
  status = STALE_STATUS,
  commits = [{oid: sha, status}],
  baseChanges = [],
  lastChanges = [],
  draft = false,
  updatedAt = hoursAgo(1),
  merged = false,
  headRepository = 'outsider/gvisor',
  branch = `branch${number}`,
} = {}) {
  return {
    number,
    author,
    sha,
    base,
    reviews,
    commits,
    baseChanges,
    lastChanges,
    draft,
    updatedAt,
    merged,
    headRepository,
    branch,
  };
}

// The statuses of a commit, keyed by context: one status of the master family,
// set by the app by default. The state is as the GraphQL API returns it.
function status(state, text, {
  context = MASTER,
  creator = {__typename: 'Bot', login: APP_SLUG},
} = {}) {
  return {[context]: {state: state.toUpperCase(), description: text, creator}};
}

// Statuses of the app that are out of date, for the two families.
const STALE_STATUS = {
  ...status('pending', 'stale'),
  ...status('pending', 'stale', {context: RELEASE}),
};

// The parameters of a status write.
function write(sha, state, text, context = MASTER) {
  return {
    owner: 'gvisor',
    repo: 'gvisor',
    sha,
    context,
    target_url: 'https://github.com/gvisor/gvisor/actions/runs/42',
    state,
    description: text,
  };
}

function activity(sha, pusher) {
  return [{after: sha, actor: pusher === null ? null : {id: pusher}}];
}

// The parameters of a pull request rule that has all rules that the script
// needs.
const RULE_PARAMETERS = {
  dismiss_stale_reviews_on_push: true,
  require_last_push_approval: true,
  required_approving_review_count: 1,
};

// The rules of a branch that has all pull request rules that the script needs.
const NEEDED_RULES = [
  {type: 'deletion'},
  {type: 'pull_request', parameters: RULE_PARAMETERS},
];

// Returns a rule that requires statuses.
function requiredStatuses(...checks) {
  return {
    type: 'required_status_checks',
    parameters: {required_status_checks: checks},
  };
}

// Returns the rules of a branch that has all rules that the script needs, and
// that requires the status of its family from the app.
function enforcedRules(branch) {
  const context = branch.startsWith('release/') ? RELEASE : MASTER;
  return [...NEEDED_RULES, requiredStatuses({context, integration_id: APP_ID})];
}

// Returns the newest `count` items of a connection, before the item at index
// `before`, with the page information of a backward pagination.
function lastPage(items, count, before = items.length) {
  const start = Math.max(0, before - count);
  return {
    pageInfo: {hasPreviousPage: start > 0, startCursor: String(start)},
    nodes: items.slice(start, before),
  };
}

// A fake of the objects that the script uses. It checks the text of the
// queries, and it applies their arguments to the pull requests.
//   prs: The open pull requests, from pullRequest.
//   closed: The closed or merged pull requests. The pull request with the
//       newest update is first.
//   activities: The newest activity of each branch, keyed by
//       "owner/repo refs/heads/branch".
//   rules: The rules of the branches that do not have enforcedRules, keyed
//       by branch.
//   accounts: The accounts that are not as the rosters say, keyed by ID.
//   statusLists: The statuses of the commits that have statuses, newest first,
//       keyed by commit. A commit can have {first, later}: the list for the
//       first read, and the list for the later reads.
//   fail: Names of the API calls that reject: 'graphql', 'closed', 'reviews',
//       'activity', 'rules', 'accounts', 'statuses', 'status', or
//       'status:SHA'.
//   unreadable: Numbers of the open pull requests that the response has as
//       null, with an error.
//   partial: Functions that change the data of an open pull request, keyed by
//       number. The response has an error in that pull request.
//   slowAbove: The largest page of open pull requests that does not fail.
//   unattributed: The path of an error of the response that is not in a pull
//       request, true for an error without a path, or 'no errors' for a
//       failure with an empty list of errors.
//   writeError: The error of a status write that rejects.
function fake({
  prs = [],
  closed = [],
  activities = {},
  rules = {},
  accounts = {},
  statusLists = {},
  fail = [],
  unreadable = [],
  partial = {},
  unattributed = false,
  slowAbove = 100,
  writeError = new Error('status failed'),
} = {}) {
  const calls = {
    graphql: [],
    closed: [],
    accounts: [],
    reviews: [],
    activity: [],
    rules: [],
    statuses: [],
    status: [],
    sleep: [],
  };
  const failed = [];
  const errors = [];
  const warnings = [];
  const states = ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'];
  const reviewsArguments = 'last: 100, states: [APPROVED, CHANGES_REQUESTED, DISMISSED]';
  const idFragment = /fragment id on Actor \{\s*\.\.\. on User \{ databaseId \}\s*\.\.\. on Bot \{ databaseId \}\s*\}/;
  const opinions = (pr) => pr.reviews.filter((r) => states.includes(r.state))
                               .map((r) => r.commit === undefined ?
                                        {...r, commit: {oid: pr.sha}} :
                                        r);

  // The head commit of a pull request, as the queries select it.
  const headCommit = (pr) => {
    const head = pr.commits.at(-1);
    if (!head) {
      // A pull request without commits.
      return {nodes: []};
    }
    // The newest status of each name.
    const contexts = Object.entries(head.status || {})
                         .map(([context, value]) => ({context, ...value}));
    // A commit without a status of any context has a null status.
    return {
      nodes: [{commit: {oid: head.oid, status: head.status ? {contexts} : null}}],
    };
  };
  const checkHeadCommit = (query) => {
    assert.match(
        query, /commits\(last: 1\) \{\s*nodes \{\s*commit \{\s*oid\s+status \{/);
    assert.match(
        query,
        /status \{\s*contexts \{\s*context\s+state\s+description\s+creator \{ __typename login \}\s*\}\s*\}/);
  };
  // The cursor of the first page is null.
  const checkPageVariables = (query, more = '') => {
    assert.ok(query.includes(
        `query($owner: String!, $repo: String!, $cursor: String${more}) {`));
  };
  const node = (pr) => ({
    number: pr.number,
    isDraft: pr.draft,
    baseRefName: pr.base,
    headRefOid: pr.sha,
    headRefName: pr.branch,
    headRepository: pr.headRepository && {nameWithOwner: pr.headRepository},
    author: pr.author === null ? null : {databaseId: pr.author},
    baseChanges: {nodes: pr.baseChanges.slice(-1).map((at) => ({createdAt: at}))},
    lastChange: {
      nodes: pr.lastChanges.slice(-1).map((id) => {
        if (id === AUTOMATIC) {
          // The query selects no field of this event.
          return {};
        }
        return {actor: id === null ? null : {databaseId: id}};
      }),
    },
    reviews: lastPage(opinions(pr), 100),
    commits: headCommit(pr),
  });

  const github = {
    graphql: async (query, variables) => {
      assert.ok(query.includes('repository(owner: $owner, name: $repo) {'));
      if (query.includes('states: [CLOSED, MERGED]')) {
        calls.closed.push(variables);
        assert.match(
            query,
            /pullRequests\(\s*states: \[CLOSED, MERGED\], first: 50, after: \$cursor,\s*orderBy: \{field: UPDATED_AT, direction: DESC\}\) \{\s*pageInfo \{ hasNextPage endCursor \}\s*nodes \{\s*updatedAt\s+merged\s+baseRefName\s+headRefOid\s/);
        checkHeadCommit(query);
        checkPageVariables(query);
        // GitHub rejects a query that has a fragment that it does not use.
        assert.doesNotMatch(query, idFragment);
        if (fail.includes('closed')) {
          throw new Error('closed failed');
        }
        const start = variables.cursor === null ? 0 : Number(variables.cursor);
        const end = start + 50;
        return {
          repository: {
            pullRequests: {
              pageInfo: {hasNextPage: end < closed.length, endCursor: String(end)},
              nodes: closed.slice(start, end).map((pr) => ({
                updatedAt: pr.updatedAt,
                merged: pr.merged,
                baseRefName: pr.base,
                headRefOid: pr.sha,
                commits: headCommit(pr),
              })),
            },
          },
        };
      }
      assert.match(query, idFragment);
      assert.ok(query.includes('pageInfo { hasPreviousPage startCursor }'));
      assert.match(
          query,
          /nodes \{ state submittedAt commit \{ oid \} author \{ \.\.\.id \} \}/);
      if (variables.number !== undefined) {
        calls.reviews.push(variables);
        assert.ok(query.includes(
            'query($owner: String!, $repo: String!, $number: Int!, $cursor: String!)'));
        assert.ok(query.includes('pullRequest(number: $number)'));
        assert.ok(query.includes(`reviews(${reviewsArguments}, before: $cursor)`));
        if (fail.includes('reviews')) {
          throw new Error('reviews failed');
        }
        const pr = prs.find((p) => p.number === variables.number);
        return {
          repository: {
            pullRequest: {
              reviews: lastPage(opinions(pr), 100, Number(variables.cursor)),
            },
          },
        };
      }
      calls.graphql.push(variables);
      if (fail.includes('graphql')) {
        throw new Error('graphql failed');
      }
      assert.match(
          query,
          /pullRequests\(\s*states: OPEN, first: \$first, after: \$cursor,\s*orderBy: \{field: CREATED_AT, direction: ASC\}\)/);
      checkPageVariables(query, ', $first: Int!');
      const size = variables.first;
      assert.ok(Number.isInteger(size) && size >= 1 && size <= 100);
      if (size > slowAbove) {
        throw new Error('timeout');
      }
      for (const field of [
             'pageInfo { hasNextPage endCursor }',
             'number\n',
             'isDraft\n',
             'baseRefName\n',
             'headRefOid\n',
             'headRefName\n',
             'headRepository { nameWithOwner }',
             `reviews(${reviewsArguments}) {`,
             '... on BaseRefChangedEvent { createdAt }',
             '... on AutomaticBaseChangeSucceededEvent { createdAt }',
           ]) {
        assert.ok(query.includes(field), field);
      }
      assert.match(query, /author \{ \.\.\.id \}\s+baseChanges: timelineItems\(/);
      assert.match(
          query,
          /lastChange: timelineItems\(\s*itemTypes: \[\s*BASE_REF_CHANGED_EVENT, AUTOMATIC_BASE_CHANGE_SUCCEEDED_EVENT,\s*REOPENED_EVENT, READY_FOR_REVIEW_EVENT\s*\],\s*last: 1\) \{\s*nodes \{\s*\.\.\. on BaseRefChangedEvent \{ actor \{ \.\.\.id \} \}\s*\.\.\. on ReopenedEvent \{ actor \{ \.\.\.id \} \}\s*\.\.\. on ReadyForReviewEvent \{ actor \{ \.\.\.id \} \}\s*\}/);
      assert.match(
          query,
          /baseChanges: timelineItems\(\s*itemTypes: \[BASE_REF_CHANGED_EVENT, AUTOMATIC_BASE_CHANGE_SUCCEEDED_EVENT\],\s*last: 1\)/);
      checkHeadCommit(query);
      const start = variables.cursor === null ? 0 : Number(variables.cursor);
      const end = start + size;
      const responseErrors = [];
      const at = ['repository', 'pullRequests', 'nodes'];
      const nodes = prs.slice(start, end).map((pr, index) => {
        if (unreadable.includes(pr.number)) {
          responseErrors.push({path: [...at, index]});
          return null;
        }
        const result = node(pr);
        if (partial[pr.number]) {
          partial[pr.number](result);
          responseErrors.push({path: [...at, index, 'reviews']});
        }
        return result;
      });
      if (unattributed && unattributed !== 'no errors') {
        responseErrors.push(unattributed === true ? {} : {path: unattributed});
      }
      const data = {
        repository: {
          pullRequests: {
            pageInfo: {hasNextPage: end < prs.length, endCursor: String(end)},
            nodes,
          },
        },
      };
      if (responseErrors.length > 0 || unattributed === 'no errors') {
        throw Object.assign(
            new Error('a field failed'), {data, errors: responseErrors});
      }
      return data;
    },
    request: async (route, params) => {
      if (route === 'GET /repos/{owner}/{repo}/rules/branches/{branch}') {
        calls.rules.push(params);
        if (fail.includes('rules')) {
          throw new Error('rules failed');
        }
        return {data: rules[params.branch] || enforcedRules(params.branch)};
      }
      if (route === 'GET /user/{account_id}') {
        calls.accounts.push(params.account_id);
        if (fail.includes('accounts')) {
          throw new Error('accounts failed');
        }
        // By default, each account is as its roster entry says.
        const id = params.account_id;
        const isBot = ROSTERS['governance/bots.yaml'].bots.find(
            (entry) => entry.github_id === id);
        const entry = isBot || ROSTERS['governance/maintainers.yaml']
                                   .maintainers.find((m) => m.github_id === id);
        return {
          data: accounts[id] ||
              {login: entry.github, type: isBot ? 'Bot' : 'User'},
        };
      }
      if (route === 'GET /repos/{owner}/{repo}/commits/{ref}/statuses') {
        calls.statuses.push(params);
        if (fail.includes('statuses')) {
          throw new Error('statuses failed');
        }
        assert.equal(params.per_page, 100);
        const lists = statusLists[params.ref] || [];
        const reads = calls.statuses.filter(
            (p) => p.ref === params.ref && p.page === 1).length;
        const list =
            Array.isArray(lists) ? lists : reads > 1 ? lists.later : lists.first;
        return {data: list.slice((params.page - 1) * 100, params.page * 100)};
      }
      assert.equal(route, 'GET /repos/{owner}/{repo}/activity');
      calls.activity.push(params);
      if (fail.includes('activity')) {
        throw new Error('activity failed');
      }
      return {data: activities[`${params.owner}/${params.repo} ${params.ref}`] || []};
    },
    rest: {
      repos: {
        createCommitStatus: async (params) => {
          calls.status.push(params);
          // GitHub rejects a longer description.
          assert.ok(params.description.length <= 140, params.description);
          if (fail.includes('status') || fail.includes(`status:${params.sha}`)) {
            throw writeError;
          }
          return {data: {}};
        },
      },
    },
  };
  return {
    calls,
    failed,
    errors,
    warnings,
    args: {
      github,
      context: {
        repo: {owner: 'gvisor', repo: 'gvisor'},
        serverUrl: 'https://github.com',
        runId: 42,
      },
      core: {
        info: () => {},
        warning: (message) => warnings.push(message),
        error: (message) => errors.push(message),
        setFailed: (message) => failed.push(message),
      },
      appSlug: APP_SLUG,
      appID: APP_ID,
      now: () => NOW,
      load: (file) => {
        const name = Object.keys(ROSTERS).find((n) => file.endsWith(n));
        assert.ok(name, file);
        return ROSTERS[name];
      },
      sleep: async (ms) => {
        calls.sleep.push(ms);
      },
    },
  };
}

function shas(count) {
  return Array.from({length: count}, (_, i) => String(i + 1).padStart(40, '0'));
}

test('sets the status of a pull request', async () => {
  const f = fake({
    prs: [pullRequest(10, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2)})],
  });
  await maintainerApproval(f.args);
  const repository = {owner: 'gvisor', repo: 'gvisor'};
  assert.deepEqual(f.calls.graphql, [{...repository, cursor: null, first: 25}]);
  assert.deepEqual(f.calls.closed, [{...repository, cursor: null}]);
  assert.deepEqual(
      f.calls.rules, [{...repository, branch: 'master', per_page: 100}]);
  assert.deepEqual(f.calls.status, [write(HEAD, 'success', description(2, 2))]);
  assert.deepEqual(f.calls.activity, []);
  assert.deepEqual(f.calls.reviews, []);
  assert.deepEqual(f.calls.sleep, [1000]);
  assert.deepEqual(f.failed, []);
  assert.deepEqual(f.errors, []);
  assert.deepEqual(f.warnings, []);
});

test('a commit gets its first status when it is successful or has an approval', async () => {
  const [a, b, c, d, e, g, h, i, j, k] = shas(10);
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const f = fake({
    prs: [
      // The author has no account.
      pullRequest(1, null, {sha: a, status: null}),
      // A maintainer approval is in effect.
      pullRequest(2, OUTSIDER1, {sha: b, status: null, reviews: approvals(ACTIVE1)}),
      // The approvals of the author and of other accounts are not maintainer
      // approvals.
      pullRequest(8, ACTIVE1, {
        sha: i,
        status: null,
        reviews: approvals(ACTIVE1, OUTSIDER1, EMERITUS),
      }),
      // An approval that is not in effect.
      pullRequest(9, OUTSIDER1, {
        sha: j,
        status: null,
        reviews: [review(ACTIVE1, 'APPROVED', '2026-01-01T00:00:00Z', OTHER)],
      }),
      // A draft with a maintainer approval.
      pullRequest(10, OUTSIDER1, {
        sha: k,
        status: null,
        draft: true,
        reviews: approvals(ACTIVE1, ACTIVE2),
      }),
      // A pull request that cannot be evaluated.
      pullRequest(3, ACTIVE1, {
        sha: c,
        status: null,
        reviews: approvals(ACTIVE2),
        headRepository: 'active1/gvisor',
      }),
      pullRequest(4, OUTSIDER1, {
        sha: d,
        status: null,
        reviews: approvals(ACTIVE1, ACTIVE2),
      }),
      // A status of another context is not a status of the family.
      pullRequest(5, OUTSIDER1, {
        sha: e,
        status: status('success', description(2, 2), {context: RELEASE}),
      }),
      // A status of another context that the app did not set does not hide a
      // status of the family.
      pullRequest(6, OUTSIDER1, {
        sha: g,
        status: status('pending', 'x', {context: RELEASE, ...other}),
      }),
      // A commit that has a status of the app. The new successful status of
      // another commit comes before its new status, which is not successful.
      pullRequest(7, OUTSIDER1, {sha: h}),
    ],
    fail: ['activity'],
  });
  const result = await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(e, 'pending', NOT_NEEDED, RELEASE),
    write(g, 'pending', NOT_NEEDED, RELEASE),
    write(d, 'success', description(2, 2)),
    write(k, 'pending', DRAFT),
    write(h, 'pending', description(0, 2)),
    write(b, 'pending', description(1, 2)),
  ]);
  assert.deepEqual(result, {commits: 10, written: 6});
  assert.deepEqual(f.errors, ['#3: cannot evaluate: activity failed']);
  assert.deepEqual(f.failed, ['1 failure(s)']);
});

test('an approval of one pull request of a commit gives the commit its first status', async () => {
  const [a, b, c, d, e, g] = shas(6);
  const one = approvals(ACTIVE1);
  const two = approvals(ACTIVE1, ACTIVE2);
  const first = 'release/20261101';
  const second = 'release/20261102';
  const f = fake({
    prs: [
      // Only the second pull request of the base branch has an approval. The
      // status is that of the pull request with the most approvals.
      pullRequest(1, OUTSIDER1, {sha: a, status: null}),
      pullRequest(2, OUTSIDER2, {sha: a, status: null, reviews: one}),
      // The first pull request has an approval.
      pullRequest(3, OUTSIDER1, {sha: b, status: null, reviews: one}),
      pullRequest(4, OUTSIDER2, {sha: b, status: null}),
      // Only the pull request to the base branch that is successful has
      // approvals. The status is that of the other base branch.
      pullRequest(5, OUTSIDER1, {sha: c, base: first, status: null, reviews: two}),
      pullRequest(6, OUTSIDER2, {sha: c, base: second, status: null}),
      // The pull request to the base branch that is not successful has an
      // approval.
      pullRequest(7, OUTSIDER1, {sha: d, base: first, status: null, reviews: two}),
      pullRequest(8, OUTSIDER2, {sha: d, base: second, status: null, reviews: one}),
      // The status of a commit with too many statuses is an error status.
      pullRequest(9, OUTSIDER1, {sha: e, status: null, reviews: two}),
      // A pull request that cannot be evaluated gives the commit no first
      // status, also when another pull request of the commit has approvals.
      pullRequest(10, OUTSIDER1, {sha: g, base: first, status: null, reviews: two}),
      pullRequest(11, OUTSIDER2, {
        sha: g,
        base: second,
        status: null,
        reviews: two,
        draft: null,
      }),
    ],
    statusLists: {[e]: Array.from({length: 1000}, () => ({context: 'ci'}))},
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(e, 'error', TOO_MANY),
    write(d, 'pending', `#8: ${description(1, 2)}`, RELEASE),
    write(c, 'pending', `#6: ${description(0, 2)}`, RELEASE),
    write(b, 'pending', description(1, 2)),
    write(a, 'pending', description(1, 2)),
  ]);
  assert.deepEqual(f.errors, ['#11: cannot evaluate: cannot read the draft state']);
});

test('the status is for the family of the base branch', async () => {
  const [a, b, c, d, e, g] = shas(6);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: a, base: 'master'}),
      pullRequest(2, OUTSIDER1, {sha: b, base: 'release/20261101'}),
      // These base branches are in no family.
      ...[
        'release',
        'release/',
        'master2',
        'my/master',
        'feature',
        'release/x',
        'release/2026110',
        'release/2026110x',
        'release/202611011',
        'release/20261101/x',
        'my/release/20261101',
      ].map((base, i) => pullRequest(3 + i, OUTSIDER1, {sha: c, base, reviews: two})),
      // The older reviews of such a pull request are not read.
      pullRequest(20, OUTSIDER1, {
        sha: c,
        base: 'feature',
        reviews: Array.from({length: 150}, () => review(ACTIVE1, 'APPROVED')),
      }),
      // A commit can be in two families. The approvals of a pull request are
      // for its family only.
      pullRequest(21, OUTSIDER1, {sha: d, base: 'release/20261101', reviews: two}),
      pullRequest(22, OUTSIDER1, {sha: d, base: 'master'}),
      // The status of another family does not make the status up to date.
      pullRequest(23, OUTSIDER1, {
        sha: e,
        base: 'master',
        status: {
          ...STALE_STATUS,
          ...status('pending', description(0, 2), {context: RELEASE}),
        },
      }),
      // A successful status of the other family with the same description is
      // not the status of this family.
      pullRequest(24, OUTSIDER1, {
        sha: g,
        base: 'release/20261101',
        reviews: two,
        status: status('success', description(2, 2)),
      }),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(g, 'pending', NOT_NEEDED),
    write(g, 'success', description(2, 2), RELEASE),
    write(d, 'success', description(2, 2), RELEASE),
    write(e, 'pending', description(0, 2)),
    write(d, 'pending', description(0, 2)),
    write(b, 'pending', description(0, 2), RELEASE),
    write(a, 'pending', description(0, 2)),
  ]);
  // Only the rules of the base branches of the families are read.
  assert.deepEqual(
      f.calls.rules.map((p) => p.branch), ['master', 'release/20261101']);
  assert.deepEqual(f.calls.reviews, []);
  assert.deepEqual(f.failed, []);
});

test('reads all pages of pull requests', async () => {
  const all = shas(120);
  const f = fake({prs: all.map((sha, i) => pullRequest(i + 1, OUTSIDER1, {sha}))});
  await maintainerApproval(f.args);
  assert.deepEqual(
      f.calls.graphql.map((v) => v.cursor), [null, '25', '50', '75', '100']);
  // The newest pull request is first.
  assert.deepEqual(f.calls.status.map((s) => s.sha), all.toReversed());
  assert.equal(f.calls.sleep.length, 120);
  assert.equal(f.calls.rules.length, 1);
});

test('reads the newest commit and the newest base change', async () => {
  const f = fake({
    prs: [pullRequest(10, OUTSIDER1, {
      commits: [
        {oid: OTHER, status: status('success', description(2, 2))},
        {oid: HEAD, status: STALE_STATUS},
      ],
      baseChanges: ['2026-02-02T00:00:00Z', '2026-02-04T00:00:00Z'],
      reviews: [
        review(ACTIVE1, 'APPROVED', '2026-02-03T00:00:00Z'),
        review(ACTIVE2, 'APPROVED', '2026-02-05T00:00:00Z'),
      ],
    })],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [write(HEAD, 'pending', description(1, 2))]);
});

test('reads all reviews that can change an opinion', async () => {
  const [a, b, c] = shas(3);
  const two = approvals(ACTIVE1, ACTIVE2);
  const many = (state, count) =>
      Array.from({length: count}, () => review(OUTSIDER2, state));
  const f = fake({
    prs: [
      // Comments do not hide older approvals.
      pullRequest(1, OUTSIDER1, {sha: a, reviews: [...two, ...many('COMMENTED', 250)]}),
      // The approvals of other accounts do not hide them.
      pullRequest(2, OUTSIDER1, {sha: b, reviews: [...two, ...many('APPROVED', 250)]}),
      // A newer request for changes is not lost.
      pullRequest(3, OUTSIDER1, {
        sha: c,
        reviews: [
          ...two,
          ...many('APPROVED', 150),
          review(ACTIVE2, 'CHANGES_REQUESTED'),
        ],
      }),
    ],
  });
  await maintainerApproval(f.args);
  const older = (number, cursor) => ({owner: 'gvisor', repo: 'gvisor', number, cursor});
  assert.deepEqual(
      f.calls.reviews, [older(2, '152'), older(2, '52'), older(3, '53')]);
  assert.deepEqual(f.calls.status, [
    write(b, 'success', description(2, 2)),
    write(a, 'success', description(2, 2)),
    write(c, 'pending', description(1, 2)),
  ]);
  assert.deepEqual(f.failed, []);
});

test('the newest review of a reviewer decides', async () => {
  const [a, b] = shas(2);
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {
        sha: a,
        reviews: [
          ...approvals(ACTIVE1, ACTIVE2),
          review(ACTIVE2, 'CHANGES_REQUESTED'),
        ],
      }),
      pullRequest(2, OUTSIDER1, {
        sha: b,
        reviews: [
          review(ACTIVE2, 'CHANGES_REQUESTED'),
          ...approvals(ACTIVE2, ACTIVE1),
        ],
      }),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'success', description(2, 2)),
    write(a, 'pending', description(1, 2)),
  ]);
});

test('reads a limited number of pages of reviews', async () => {
  const [a, b, c] = shas(3);
  const flood = (count) =>
      Array.from({length: count}, () => review(OUTSIDER2, 'APPROVED'));
  const f = fake({
    prs: [
      // The first page and 2 older pages have all reviews.
      pullRequest(1, OUTSIDER1, {
        sha: a,
        reviews: [...approvals(ACTIVE1, ACTIVE2), ...flood(298)],
      }),
      // One review more: the oldest approval is not read.
      pullRequest(2, OUTSIDER1, {
        sha: b,
        reviews: [...approvals(ACTIVE1, ACTIVE2), ...flood(299)],
        status: status('success', description(2, 2)),
      }),
      // A reviewer can approve again.
      pullRequest(3, OUTSIDER1, {
        sha: c,
        reviews: [...approvals(ACTIVE1, ACTIVE2), ...flood(2000), ...approvals(ACTIVE1)],
      }),
    ],
  });
  await maintainerApproval(f.args);
  for (const number of [1, 2, 3]) {
    assert.equal(f.calls.reviews.filter((v) => v.number === number).length, 2);
  }
  assert.deepEqual(f.calls.status, [
    write(b, 'pending', description(1, 2)),
    write(a, 'success', description(2, 2)),
    write(c, 'pending', description(1, 2)),
  ]);
  assert.deepEqual(f.warnings, [
    '#2: only the newest 300 reviews are read',
    '#3: only the newest 300 reviews are read',
  ]);
  assert.deepEqual(f.failed, []);
});

test('does not set a status that is up to date', async () => {
  const pending = description(0, 2);
  const success = description(2, 2);
  const all = shas(9);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      // Up to date.
      pullRequest(1, OUTSIDER1, {sha: all[0], status: status('pending', pending)}),
      pullRequest(2, OUTSIDER1, {
        sha: all[1],
        reviews: two,
        status: status('success', success),
      }),
      pullRequest(3, OUTSIDER1, {
        sha: all[2],
        base: 'release/20261101',
        status: status('pending', pending, {context: RELEASE}),
      }),
      // Out of date: another state.
      pullRequest(4, OUTSIDER1, {sha: all[3], status: status('success', success)}),
      pullRequest(5, OUTSIDER1, {
        sha: all[4],
        reviews: two,
        status: status('error', ERROR),
      }),
      pullRequest(6, OUTSIDER1, {sha: all[5], status: status('expected', pending)}),
      // Out of date: another description.
      pullRequest(7, OUTSIDER1, {
        sha: all[6],
        status: status('pending', description(1, 2)),
      }),
      pullRequest(8, OUTSIDER1, {sha: all[7], status: status('pending', null)}),
      // Out of date: an error status of a pull request that can be evaluated
      // again.
      pullRequest(9, OUTSIDER1, {sha: all[8], status: status('error', ERROR)}),
    ],
  });
  await maintainerApproval(f.args);
  // First the successful statuses that are out of date, then the new
  // successful statuses, then the others. The newest pull request is first.
  assert.deepEqual(f.calls.status, [
    write(all[3], 'pending', pending),
    write(all[4], 'success', success),
    write(all[8], 'pending', pending),
    write(all[7], 'pending', pending),
    write(all[6], 'pending', pending),
    write(all[5], 'pending', pending),
  ]);
  assert.equal(f.calls.sleep.length, 6);
});

test('a status that the app did not set hides the status of the app', async () => {
  const pending = description(0, 2);
  const all = shas(7);
  const creators = [
    {__typename: 'User', login: APP_SLUG},
    {__typename: 'Bot', login: 'github-actions'},
    {__typename: 'Bot', login: `${APP_SLUG}[bot]`},
    null,
  ];
  const f = fake({
    prs: [
      ...creators.map(
          (creator, i) => pullRequest(i + 1, OUTSIDER1, {
            sha: all[i],
            status: status('pending', pending, {creator}),
          })),
      // A new successful status in place of a status of the app.
      pullRequest(5, OUTSIDER1, {sha: all[4], reviews: approvals(ACTIVE1, ACTIVE2)}),
      // A new successful status in place of a hidden status.
      pullRequest(6, OUTSIDER1, {
        sha: all[5],
        reviews: approvals(ACTIVE1, ACTIVE2),
        status: status('pending', pending, {creator: creators[1]}),
      }),
      // A successful status that the app did not set.
      pullRequest(7, OUTSIDER1, {
        sha: all[6],
        status: status('success', description(2, 2), {creator: creators[1]}),
      }),
    ],
  });
  await maintainerApproval(f.args);
  // The hidden status can be successful: these commits come before the new
  // successful statuses.
  assert.deepEqual(f.calls.status, [
    write(all[6], 'pending', pending),
    ...all.slice(0, 4).toReversed().map((sha) => write(sha, 'pending', pending)),
    write(all[5], 'success', description(2, 2)),
    write(all[4], 'success', description(2, 2)),
  ]);
  // The statuses of these commits can be read.
  assert.deepEqual(f.failed, []);
});

test('evaluates a pull request without its head commit in the response', async () => {
  const [a, b, c] = shas(3);
  const f = fake({
    prs: [
      // The statuses of these pull requests are not known.
      pullRequest(10, OUTSIDER1, {
        sha: a,
        commits: [{oid: OTHER, status: status('pending', description(0, 2))}],
      }),
      pullRequest(11, OUTSIDER1, {
        sha: b,
        commits: [{oid: OTHER}],
        reviews: approvals(ACTIVE1, ACTIVE2),
      }),
      pullRequest(12, OUTSIDER1, {sha: c}),
      // The base branch is in no family.
      pullRequest(13, OUTSIDER1, {sha: c, base: 'feature', commits: [{oid: OTHER}]}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(a, 'pending', description(0, 2)),
    write(b, 'success', description(2, 2)),
    write(c, 'pending', description(0, 2)),
  ]);
  assert.deepEqual(f.errors, [
    '#10: cannot read the status of the head commit',
    '#11: cannot read the status of the head commit',
    '#13: cannot read the status of the head commit',
  ]);
  assert.deepEqual(f.failed, ['3 failure(s)']);
});

test('one successful pull request is sufficient for a base branch', async () => {
  const [a, b, c, d, e, g] = shas(6);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      // The newest pull request of a commit decides the order of the writes.
      pullRequest(5, OUTSIDER1, {sha: e, reviews: two}),
      // The first pull request is successful.
      pullRequest(10, OUTSIDER1, {sha: a, reviews: two}),
      pullRequest(11, OUTSIDER2, {sha: a}),
      // The second pull request is successful.
      pullRequest(20, OUTSIDER1, {sha: b}),
      pullRequest(21, OUTSIDER2, {sha: b, reviews: two}),
      // No pull request is successful: the status is that of the one with the
      // most approvals.
      pullRequest(30, OUTSIDER1, {sha: c, reviews: approvals(ACTIVE1)}),
      pullRequest(31, OUTSIDER2, {sha: c}),
      // The approvals of two pull requests do not add up.
      pullRequest(40, OUTSIDER1, {sha: d, reviews: approvals(ACTIVE1)}),
      pullRequest(41, OUTSIDER2, {sha: d, reviews: approvals(ACTIVE2)}),
      pullRequest(50, OUTSIDER2, {sha: e}),
      // Two pull requests are successful: the status is that of the first one.
      pullRequest(60, OUTSIDER1, {sha: g, reviews: two}),
      pullRequest(61, OUTSIDER2, {sha: g, reviews: approvals(ACTIVE1, ACTIVE2, HIATUS)}),
    ],
  });
  const result = await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(g, 'success', description(2, 2)),
    write(e, 'success', description(2, 2)),
    write(b, 'success', description(2, 2)),
    write(a, 'success', description(2, 2)),
    write(d, 'pending', description(1, 2)),
    write(c, 'pending', description(1, 2)),
  ]);
  // The pull requests of a commit count as one.
  assert.deepEqual(result, {commits: 6, written: 6});
});

test('each base branch of a family needs a successful pull request', async () => {
  const [a, b, c, d] = shas(4);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      // No base branch has a successful pull request: the status is that of
      // the first base branch.
      pullRequest(1, OUTSIDER1, {
        sha: d,
        base: 'release/20261101',
        reviews: approvals(ACTIVE1),
      }),
      pullRequest(2, OUTSIDER1, {sha: d, base: 'release/20261102'}),
      pullRequest(10, OUTSIDER1, {sha: a, base: 'release/20261101', reviews: two}),
      pullRequest(11, OUTSIDER1, {sha: a, base: 'release/20261102'}),
      pullRequest(20, OUTSIDER1, {sha: b, base: 'release/20261101', reviews: two}),
      pullRequest(21, OUTSIDER1, {
        sha: b,
        base: 'release/20261102',
        reviews: approvals(ACTIVE1, HIATUS),
      }),
      // One successful pull request is sufficient for each base branch.
      pullRequest(30, OUTSIDER1, {sha: c, base: 'release/20261101', reviews: two}),
      pullRequest(31, OUTSIDER1, {sha: c, base: 'release/20261101'}),
      pullRequest(32, OUTSIDER1, {sha: c, base: 'release/20261102', reviews: two}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(c, 'success', `#30: ${description(2, 2)}`, RELEASE),
    write(b, 'success', `#20: ${description(2, 2)}`, RELEASE),
    write(a, 'pending', `#11: ${description(0, 2)}`, RELEASE),
    write(d, 'pending', `#1: ${description(1, 2)}`, RELEASE),
  ]);
  assert.deepEqual(
      f.calls.rules.map((p) => p.branch), ['release/20261101', 'release/20261102']);
});

test('an approval before a change of the base branch does not count', async () => {
  const f = fake({
    prs: [pullRequest(10, OUTSIDER1, {
      baseChanges: ['2026-02-02T00:00:00Z'],
      reviews: [
        review(ACTIVE1, 'APPROVED', '2026-02-01T00:00:00Z'),
        review(ACTIVE2, 'APPROVED', '2026-02-03T00:00:00Z'),
      ],
    })],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [write(HEAD, 'pending', description(1, 2))]);
});

test('an approval of another commit does not count', async () => {
  const [a, b, c] = shas(3);
  const at = '2026-02-01T00:00:00Z';
  const f = fake({
    prs: [
      // GitHub did not move the approval to the head commit.
      pullRequest(1, OUTSIDER1, {
        sha: a,
        reviews: [
          review(ACTIVE1, 'APPROVED', at, {oid: OTHER}),
          review(ACTIVE2, 'APPROVED'),
        ],
      }),
      // An approval of the head commit after an approval of another commit.
      pullRequest(2, OUTSIDER1, {
        sha: b,
        reviews: [
          review(ACTIVE1, 'APPROVED', at, {oid: OTHER}),
          review(ACTIVE1, 'APPROVED'),
          review(ACTIVE2, 'APPROVED'),
        ],
      }),
      // An approval of another commit after an approval of the head commit.
      pullRequest(3, OUTSIDER1, {
        sha: c,
        reviews: [
          review(ACTIVE1, 'APPROVED'),
          review(ACTIVE2, 'APPROVED'),
          review(ACTIVE1, 'APPROVED', at, {oid: OTHER}),
        ],
      }),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'success', description(2, 2)),
    write(c, 'pending', description(1, 2)),
    write(a, 'pending', description(1, 2)),
  ]);
});

test('a second run sets no status', async () => {
  const all = shas(12);
  const two = approvals(ACTIVE1, ACTIVE2);
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const scenario = () => ({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: all[0]}),
      pullRequest(2, OUTSIDER1, {sha: all[1], reviews: two}),
      pullRequest(3, ACTIVE1, {sha: all[2], reviews: approvals(ACTIVE2)}),
      pullRequest(4, BOT, {sha: all[3]}),
      // A commit of two pull requests, and a commit in two families.
      pullRequest(5, OUTSIDER1, {sha: all[4], reviews: two}),
      pullRequest(6, OUTSIDER2, {sha: all[4]}),
      pullRequest(7, OUTSIDER1, {sha: all[5], base: 'release/20261101', reviews: two}),
      pullRequest(8, OUTSIDER1, {sha: all[5], base: 'release/20261102'}),
      pullRequest(9, OUTSIDER1, {sha: all[5]}),
      // Statuses that are out of date, or that the app did not set.
      pullRequest(10, OUTSIDER1, {
        sha: all[6],
        status: status('success', description(2, 2)),
      }),
      pullRequest(11, OUTSIDER1, {
        sha: all[7],
        reviews: two,
        status: status('pending', 'x', other),
      }),
      pullRequest(12, OUTSIDER1, {
        sha: all[8],
        base: 'feature',
        status: status('success', description(2, 2)),
      }),
      pullRequest(13, OUTSIDER1, {
        sha: all[9],
        base: 'feature',
        status: status('success', 'x', other),
      }),
    ],
    closed: [
      pullRequest(20, OUTSIDER1, {
        sha: all[10],
        status: status('success', description(2, 2)),
      }),
      pullRequest(21, OUTSIDER1, {
        sha: all[11],
        status: status('success', description(2, 2), {context: RELEASE}),
      }),
    ],
  });
  // A run without a failure, and the states in which a run cannot read all
  // of its inputs.
  const variants = [
    {},
    {fail: ['activity']},
    {fail: ['rules']},
    {rules: {master: []}},
    {fail: ['closed']},
    {fail: ['reviews']},
    {unreadable: [1]},
    {partial: {2: () => {}, 12: () => {}}},
    {load: () => ({})},
  ];
  for (const {load, ...variant} of variants) {
    const state = scenario();
    const run = async () => {
      const f = fake({...state, ...variant});
      await maintainerApproval(load ? {...f.args, load} : f.args);
      // The statuses that the run set are now the newest statuses of the app.
      for (const {sha, context, state: newState, description: text} of f.calls.status) {
        for (const pr of [...state.prs, ...state.closed]) {
          const head = pr.commits.at(-1);
          if (head.oid === sha) {
            head.status = {...head.status, ...status(newState, text, {context})};
          }
        }
      }
      return f.calls.status;
    };
    const first = await run();
    assert.ok(first.length > 0, JSON.stringify(variant));
    assert.deepEqual(await run(), [], JSON.stringify(variant));
  }
});

test('sets no successful status on a commit with too many statuses', async () => {
  const all = shas(11);
  const releaseBranch = 'release/20261101';
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const two = approvals(ACTIVE1, ACTIVE2);
  const list = (own, others = 0, release = 0) => [
    ...Array.from({length: others}, () => ({context: 'ci'})),
    ...Array.from({length: release}, () => ({context: RELEASE})),
    ...Array.from({length: own}, () => ({context: MASTER})),
  ];
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: all[0], reviews: two}),
      pullRequest(2, OUTSIDER1, {sha: all[1], reviews: two}),
      // The statuses of the other contexts do not count.
      pullRequest(3, OUTSIDER1, {sha: all[2], reviews: two}),
      // The statuses are on more than one page.
      pullRequest(4, OUTSIDER1, {sha: all[3], reviews: two}),
      // The pages do not have all statuses.
      pullRequest(5, OUTSIDER1, {sha: all[4], reviews: two}),
      // A successful status stays, and a status that is not successful is set.
      pullRequest(6, OUTSIDER1, {
        sha: all[5],
        reviews: two,
        status: status('success', description(2, 2)),
      }),
      pullRequest(7, OUTSIDER1, {sha: all[6]}),
      // A successful status with a new description is a new status.
      pullRequest(20, OUTSIDER1, {
        sha: 'c'.repeat(40),
        reviews: approvals(ACTIVE1, ACTIVE2, HIATUS),
        status: status('success', description(2, 2)),
      }),
      pullRequest(21, OUTSIDER1, {
        sha: 'd'.repeat(40),
        reviews: approvals(ACTIVE1, ACTIVE2, HIATUS),
        status: status('success', description(2, 2)),
      }),
      // The error status is up to date.
      pullRequest(8, OUTSIDER1, {
        sha: all[7],
        reviews: two,
        status: status('error', TOO_MANY),
      }),
      // Only the statuses of the family of the pull request count.
      pullRequest(9, OUTSIDER1, {sha: all[8], base: releaseBranch, reviews: two}),
      pullRequest(10, OUTSIDER1, {sha: all[9], base: releaseBranch, reviews: two}),
      // A status that is not known does not prevent the count.
      pullRequest(11, OUTSIDER1, {
        sha: all[10],
        reviews: two,
        status: status('pending', 'x', other),
      }),
    ],
    statusLists: {
      ['c'.repeat(40)]: list(499),
      ['d'.repeat(40)]: list(500),
      [all[0]]: list(499),
      [all[1]]: list(500),
      [all[2]]: list(100, 250, 449),
      [all[3]]: list(500, 450),
      [all[4]]: list(0, 1000),
      [all[5]]: list(900),
      [all[6]]: list(900),
      [all[7]]: list(600),
      [all[8]]: list(500, 0, 499),
      [all[9]]: list(0, 0, 500),
      [all[10]]: list(600),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    // The successful statuses, and the status that is not known and that can
    // be successful, come first.
    write('d'.repeat(40), 'error', TOO_MANY),
    write('c'.repeat(40), 'success', description(3, 2)),
    write(all[10], 'error', TOO_MANY),
    write(all[8], 'success', description(2, 2), RELEASE),
    write(all[2], 'success', description(2, 2)),
    write(all[0], 'success', description(2, 2)),
    write(all[9], 'error', TOO_MANY, RELEASE),
    write(all[6], 'pending', description(0, 2)),
    write(all[4], 'error', TOO_MANY),
    write(all[3], 'error', TOO_MANY),
    write(all[1], 'error', TOO_MANY),
  ]);
  const pages = (sha) => f.calls.statuses.filter((p) => p.ref === sha).map((p) => p.page);
  const five = [1, 2, 3, 4, 5];
  const eight = [...five, 6, 7, 8];
  const ten = [...eight, 9, 10];
  // The statuses are counted again before a successful status is set.
  const twice = (list) => [...list, ...list];
  assert.deepEqual(
      all.map(pages),
      [twice(five), five, twice(eight), ten, ten, [], [], five, twice(ten), five, five]);
  assert.deepEqual(f.failed, []);
});

test('a failure to count the statuses sets an error status', async () => {
  const [a, b, c] = shas(3);
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2)}),
      pullRequest(2, OUTSIDER1, {sha: OTHER}),
      // A commit without a status gets no status.
      pullRequest(3, OUTSIDER1, {
        sha: a,
        status: null,
        reviews: approvals(ACTIVE1, ACTIVE2),
      }),
      // A successful status with an old description stays.
      pullRequest(4, OUTSIDER1, {
        sha: b,
        status: status('success', description(2, 2)),
        reviews: approvals(ACTIVE1, ACTIVE2, HIATUS),
      }),
      // A status that is not known does not stay. The error status comes
      // before the other statuses.
      pullRequest(5, OUTSIDER1, {
        sha: c,
        status: status('pending', 'x', other),
        reviews: approvals(ACTIVE1, ACTIVE2),
      }),
    ],
    fail: ['statuses'],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(c, 'error', ERROR),
    write(OTHER, 'pending', description(0, 2)),
    write(HEAD, 'error', ERROR),
  ]);
  assert.deepEqual(f.errors, [
    `${HEAD}: cannot count the statuses: statuses failed`,
    `${a}: cannot count the statuses: statuses failed`,
    `${b}: cannot count the statuses: statuses failed`,
    `${c}: cannot count the statuses: statuses failed`,
  ]);
  assert.deepEqual(f.failed, ['4 failure(s)']);
});

test('the reviews are in the order of their submission', async () => {
  const [a, b] = shas(2);
  const early = '2026-02-01T00:00:00Z';
  const late = '2026-02-02T00:00:00Z';
  const f = fake({
    prs: [
      // The response has the request for changes first, but it is newer.
      pullRequest(1, OUTSIDER1, {
        sha: a,
        reviews: [
          review(ACTIVE1, 'CHANGES_REQUESTED', late),
          review(ACTIVE1, 'APPROVED', early),
          review(ACTIVE2, 'APPROVED', early),
        ],
      }),
      // For equal times, the order of the response decides.
      pullRequest(2, OUTSIDER1, {
        sha: b,
        reviews: [
          review(ACTIVE1, 'CHANGES_REQUESTED', early),
          review(ACTIVE1, 'APPROVED', early),
          review(ACTIVE2, 'APPROVED', late),
        ],
      }),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'success', description(2, 2)),
    write(a, 'pending', description(1, 2)),
  ]);
});

test('the status of a pull request with an error in its data is not known', async () => {
  const [a, b, c, d] = shas(4);
  const two = approvals(ACTIVE1, ACTIVE2);
  // The response has no status for the head commit, but the commit can have a
  // successful status.
  const noStatus = (node) => {
    node.commits.nodes[0].commit.status = null;
  };
  const options = {
    prs: [
      pullRequest(1, OUTSIDER1, {
        sha: a,
        reviews: two,
        status: status('success', description(2, 2)),
      }),
      pullRequest(2, OUTSIDER1, {sha: b, reviews: two}),
      // The response has a status of the app that is not successful.
      pullRequest(3, OUTSIDER1, {sha: c}),
      // A second pull request of the commit, without an error in its data,
      // does not make the status known.
      pullRequest(4, OUTSIDER1, {sha: d, status: status('success', description(2, 2))}),
      pullRequest(5, OUTSIDER2, {sha: d, status: status('success', description(2, 2))}),
    ],
    partial: {1: noStatus, 3: () => {}, 4: noStatus},
  };
  const f = fake(options);
  await maintainerApproval(f.args);
  // The error statuses come before the new successful status.
  assert.deepEqual(f.calls.status, [
    write(d, 'error', ERROR),
    write(c, 'error', ERROR),
    write(a, 'error', ERROR),
    write(b, 'success', description(2, 2)),
  ]);

  const withoutRosters = fake(options);
  await maintainerApproval({
    ...withoutRosters.args,
    load: () => {
      throw new Error('yq failed');
    },
  });
  assert.deepEqual(
      withoutRosters.calls.status,
      [write(d, 'error', ERROR), write(c, 'error', ERROR), write(a, 'error', ERROR)]);
});

test('the rulesets of the base branch must have the pull request rules', async () => {
  const [a, b, c, d, e, g, h] = shas(7);
  const two = approvals(ACTIVE1, ACTIVE2);
  const success = status('success', description(2, 2));
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const rule = (parameters) =>
      ({type: 'pull_request', parameters: {...RULE_PARAMETERS, ...parameters}});
  const DISMISS = 'dismiss stale approvals';
  const APPROVAL = 'require one approval';
  const LAST_PUSH = 'require the approval of the most recent push';
  const ALL = [DISMISS, APPROVAL, LAST_PUSH];
  const cases = [
    {name: 'no rules', rules: [], missing: ALL},
    {name: 'no pull request rule', rules: [{type: 'deletion'}], missing: ALL},
    {
      name: 'a pull request rule without parameters',
      rules: [{type: 'pull_request'}],
      missing: ALL,
    },
    {
      name: 'another rule with the parameters',
      rules: [{type: 'update', parameters: RULE_PARAMETERS}],
      missing: ALL,
    },
    {
      name: 'a pull request rule that does not dismiss',
      rules: [rule({dismiss_stale_reviews_on_push: false})],
      missing: [DISMISS],
    },
    {
      name: 'a pull request rule that requires no approval',
      rules: [rule({required_approving_review_count: 0})],
      missing: [APPROVAL],
    },
    {
      name: 'a number of approvals that is not a number',
      rules: [rule({required_approving_review_count: '1'})],
      missing: [APPROVAL],
    },
    {
      name: 'a pull request rule without the approval of the most recent push',
      rules: [rule({require_last_push_approval: false})],
      missing: [LAST_PUSH],
    },
    {
      name: 'a pull request rule with one of the rules',
      rules: [{type: 'pull_request', parameters: {require_last_push_approval: true}}],
      missing: [DISMISS, APPROVAL],
    },
  ];
  for (const {name, rules, missing, fail} of cases) {
    const f = fake({
      prs: [
        // A successful status is not kept.
        pullRequest(1, OUTSIDER1, {sha: a, reviews: two, status: success}),
        // A status that is not known can be successful.
        pullRequest(2, OUTSIDER1, {sha: b, commits: [{oid: OTHER}], reviews: two}),
        // No status is set for the other commits.
        pullRequest(3, OUTSIDER1, {sha: c, reviews: two}),
        pullRequest(4, OUTSIDER1, {sha: d, status: status('pending', 'x')}),
        // Each base branch has its own rules.
        pullRequest(5, OUTSIDER1, {sha: e, base: 'release/20261101', reviews: two}),
        // A status that the app did not set can hide a successful status.
        pullRequest(6, OUTSIDER1, {sha: g, status: status('pending', 'x', other)}),
        // A commit without a status gets no successful status.
        pullRequest(7, OUTSIDER1, {sha: h, status: null, reviews: two}),
      ],
      rules: fail ? {} : {master: rules},
      fail: fail || [],
    });
    await maintainerApproval(f.args);
    assert.deepEqual(
        f.calls.status,
        [
          write(a, 'error', ERROR),
          write(g, 'error', ERROR),
          write(b, 'error', ERROR),
          ...(fail ? [] : [write(e, 'success', description(2, 2), RELEASE)]),
        ],
        name);
    assert.deepEqual(
        f.errors.filter((message) => !message.startsWith('#')),
        fail ?
            [
              'cannot read the rules of master: rules failed',
              'cannot read the rules of release/20261101: rules failed',
            ] :
            [`no ruleset of master has these rules: ${missing.join(', ')}`],
        name);
  }
});

test('the rulesets must require the status of the family from the app only', async () => {
  const two = approvals(ACTIVE1, ACTIVE2);
  const required = (...checks) => [...NEEDED_RULES, requiredStatuses(...checks)];
  const own = {context: MASTER, integration_id: APP_ID};
  const SOURCE = `require ${MASTER} from the app only`;
  const OTHER_FAMILY = `do not require ${RELEASE}`;
  const cases = [
    {rules: required(own)},
    {rules: required({context: 'ci'}, own)},
    // GitHub does not distinguish the case of the letters.
    {rules: required({context: MASTER.toUpperCase(), integration_id: APP_ID})},
    // Another source, or each source.
    {rules: required({context: MASTER}), missing: [SOURCE]},
    {rules: required({context: MASTER, integration_id: null}), missing: [SOURCE]},
    {rules: required({context: MASTER, integration_id: 15368}), missing: [SOURCE]},
    {rules: required({context: MASTER, integration_id: String(APP_ID)}), missing: [SOURCE]},
    {rules: required({context: MASTER.toUpperCase()}), missing: [SOURCE]},
    // One of two rules has another source.
    {rules: [...required(own), ...required({context: MASTER})], missing: [SOURCE]},
    // The status of the other family.
    {rules: required(own, {context: RELEASE, integration_id: APP_ID}), missing: [OTHER_FAMILY]},
    {rules: required({context: RELEASE.toUpperCase()}), missing: [OTHER_FAMILY]},
    {rules: required({context: MASTER}, {context: RELEASE}), missing: [SOURCE, OTHER_FAMILY]},
  ];
  for (const c of cases) {
    const f = fake({
      prs: [
        pullRequest(1, OUTSIDER1, {reviews: two}),
        // Each branch has its own rules.
        pullRequest(2, OUTSIDER1, {sha: OTHER, base: 'release/20261101', reviews: two}),
      ],
      rules: {master: c.rules},
    });
    await maintainerApproval(f.args);
    const name = JSON.stringify(c);
    assert.deepEqual(
        f.calls.status.map((s) => `${s.context} ${s.state}`),
        [`${RELEASE} success`, ...(c.missing ? [] : [`${MASTER} success`])],
        name);
    assert.deepEqual(
        f.errors,
        c.missing ?
            [`no ruleset of master has these rules: ${c.missing.join(', ')}`] : [],
        name);
  }
});

test('reports the rules that do not require the status or two approvals', async () => {
  const two = approvals(ACTIVE1, ACTIVE2);
  const rule = (count) => ({
    type: 'pull_request',
    parameters: {...RULE_PARAMETERS, required_approving_review_count: count},
  });
  const cases = [
    // One approval, and no status of the family.
    {rules: NEEDED_RULES, enforced: false},
    {rules: [...NEEDED_RULES, requiredStatuses({context: 'ci'})], enforced: false},
    {rules: [...NEEDED_RULES, {type: 'required_status_checks'}], enforced: false},
    // Two approvals.
    {rules: [rule(2)], enforced: true},
    {rules: [rule(1), rule(3)], enforced: true},
    // The status of the family.
    {rules: enforcedRules('master'), enforced: true},
  ];
  for (const c of cases) {
    const f = fake({
      prs: [pullRequest(1, OUTSIDER1, {reviews: two})],
      rules: {master: c.rules},
    });
    await maintainerApproval(f.args);
    const name = JSON.stringify(c);
    // The statuses are set in each case.
    assert.deepEqual(f.calls.status, [write(HEAD, 'success', description(2, 2))], name);
    assert.deepEqual(
        f.errors,
        c.enforced ? [] :
            [`the rules of master do not require ${MASTER}, and they do not ` +
             'require two approvals'],
        name);
    assert.deepEqual(f.failed, c.enforced ? [] : ['1 failure(s)'], name);
  }
});

test('rules that cannot be read give no new successful status', async () => {
  const [a, b, c, d, e, g, h] = shas(7);
  const two = approvals(ACTIVE1, ACTIVE2);
  const success = status('success', description(2, 2));
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const variants = [
    {fail: ['rules'], error: 'rules failed'},
    {
      rules: {master: Array.from({length: 100}, () => ({type: 'deletion'}))},
      error: 'too many rules',
    },
  ];
  for (const {error, ...variant} of variants) {
    const f = fake({
      prs: [
        // A successful status that is correct stays, also with a description
        // that is out of date.
        pullRequest(1, OUTSIDER1, {sha: a, reviews: two, status: success}),
        pullRequest(2, OUTSIDER1, {
          sha: b,
          reviews: approvals(ACTIVE1, ACTIVE2, HIATUS),
          status: success,
        }),
        // A successful status that is out of date is replaced.
        pullRequest(3, OUTSIDER1, {sha: c, status: success}),
        // No new successful status.
        pullRequest(4, OUTSIDER1, {sha: d, reviews: two}),
        pullRequest(5, OUTSIDER1, {sha: e, reviews: two, status: null}),
        pullRequest(6, OUTSIDER1, {
          sha: g,
          reviews: two,
          status: status('pending', 'x', other),
        }),
        // The statuses that are not successful are set.
        pullRequest(7, OUTSIDER1, {sha: h, reviews: approvals(ACTIVE1), status: null}),
      ],
      ...variant,
    });
    await maintainerApproval(f.args);
    assert.deepEqual(
        f.calls.status,
        [
          write(c, 'pending', description(0, 2)),
          write(h, 'pending', description(1, 2)),
        ],
        error);
    assert.deepEqual(f.errors, [`cannot read the rules of master: ${error}`]);
  }
});

test('a status name with other letter cases hides the status of the app', async () => {
  const [a, b, c, d] = shas(4);
  const two = approvals(ACTIVE1, ACTIVE2);
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const variant = MASTER.toUpperCase();
  const f = fake({
    prs: [
      // GitHub has one newest status for all letter cases of a name. Another
      // account set it.
      pullRequest(1, OUTSIDER1, {
        sha: a,
        status: status('success', description(2, 2), {context: variant, ...other}),
      }),
      // The name does not have the letters of the name of the app status.
      pullRequest(2, OUTSIDER1, {
        sha: b,
        reviews: two,
        status: status('success', description(2, 2), {context: variant}),
      }),
      // The exact name: the status of the app is up to date.
      pullRequest(3, OUTSIDER1, {
        sha: c,
        reviews: two,
        status: status('success', description(2, 2)),
      }),
      // The status of the other family, with other letters.
      pullRequest(4, OUTSIDER1, {
        sha: d,
        status: status('success', 'x', {context: RELEASE.toUpperCase(), ...other}),
      }),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(a, 'pending', description(0, 2)),
    write(d, 'pending', NOT_NEEDED, RELEASE),
    write(b, 'success', description(2, 2)),
  ]);
  assert.deepEqual(f.failed, []);
});

test('sets no successful status with data that is too old', async () => {
  const [a, b, c] = shas(3);
  const prs = [
    pullRequest(1, OUTSIDER1, {sha: a, reviews: approvals(ACTIVE1, ACTIVE2)}),
    pullRequest(2, OUTSIDER1, {sha: b}),
    // The replacement of this successful status is the first write.
    pullRequest(3, OUTSIDER1, {sha: c, status: status('success', description(2, 2))}),
  ];
  // The time that the first write takes.
  for (const [delay, late] of [[120000, false], [120001, true]]) {
    const f = fake({prs});
    let time = NOW;
    await maintainerApproval({
      ...f.args,
      now: () => time,
      sleep: async () => {
        time += time === NOW ? delay : 0;
      },
    });
    assert.deepEqual(
        f.calls.status,
        [
          write(c, 'pending', description(0, 2)),
          ...(late ? [] : [write(a, 'success', description(2, 2))]),
          write(b, 'pending', description(0, 2)),
        ],
        String(delay));
    assert.deepEqual(
        f.warnings,
        late ? [`${a} master: the data is too old for a successful status`] : []);
    assert.deepEqual(f.failed, []);
  }
});

test('a branch with too many rules is not examined', async () => {
  const f = fake({
    prs: [pullRequest(1, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2)})],
    rules: {
      master: [
        ...enforcedRules('master'),
        ...Array.from({length: 97}, () => ({type: 'deletion'})),
      ],
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, []);
  assert.deepEqual(f.errors, ['cannot read the rules of master: too many rules']);
});

test('counts the statuses again before a successful status is set', async () => {
  const [a, b, c] = shas(3);
  const two = approvals(ACTIVE1, ACTIVE2);
  const list = (count) => Array.from({length: count}, () => ({context: MASTER}));
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: a, reviews: two}),
      // The commit gets more statuses after the first count.
      pullRequest(2, OUTSIDER1, {sha: b, reviews: two}),
      // The statuses with other letter cases count.
      pullRequest(3, OUTSIDER1, {sha: c, reviews: two}),
    ],
    statusLists: {
      [a]: {first: list(499), later: list(499)},
      [b]: {first: list(499), later: list(500)},
      [c]: Array.from({length: 500}, () => ({context: MASTER.toUpperCase()})),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(a, 'success', description(2, 2)),
    write(c, 'error', TOO_MANY),
  ]);
  assert.deepEqual(
      f.errors, [`${b} master: too many statuses for a successful status`]);

  // A failure of the second count sets no successful status.
  const g = fake({
    prs: [pullRequest(1, OUTSIDER1, {sha: a, reviews: two})],
    statusLists: {
      [a]: {
        first: [],
        get later() {
          throw new Error('statuses failed later');
        },
      },
    },
  });
  await maintainerApproval(g.args);
  assert.deepEqual(g.calls.status, []);
  assert.deepEqual(g.errors, [`${a}: cannot count the statuses: statuses failed later`]);
});

test('reports the differences between the rosters and the accounts', async () => {
  const prs = [pullRequest(1, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2)})];
  const f = fake({prs});
  await maintainerApproval(f.args);
  // The maintainers that are not emeritus, and the bots.
  assert.deepEqual(f.calls.accounts.toSorted(), [ACTIVE1, ACTIVE2, HIATUS, BOT].toSorted());
  assert.deepEqual(f.failed, []);

  // A difference is a failure, and it does not change the statuses.
  const g = fake({prs, accounts: {[ACTIVE2]: {login: 'other', type: 'User'}}});
  await maintainerApproval(g.args);
  assert.deepEqual(g.calls.status, f.calls.status);
  assert.equal(g.errors.length, 1);
  assert.match(g.errors[0], /^roster: active2 \(\d+\) must be a User: /);
  assert.deepEqual(g.failed, ['1 failure(s)']);

  const h = fake({prs, fail: ['accounts']});
  await maintainerApproval(h.args);
  assert.deepEqual(h.calls.status, f.calls.status);
  assert.deepEqual(
      h.errors, ['cannot compare the rosters with the accounts: accounts failed']);
});

test('the ID of the app is necessary', async () => {
  for (const appID of [undefined, null, 0, -1, 1.5, '4242', NaN]) {
    const f = fake({prs: [pullRequest(1, OUTSIDER1)]});
    await assert.rejects(
        maintainerApproval({...f.args, appID}), /the ID of the GitHub App is not set/,
        String(appID));
    assert.deepEqual(f.calls.graphql, []);
  }
});

test('reads a smaller page of pull requests after a failure', async () => {
  const all = shas(30);
  const prs = all.map((sha, i) => pullRequest(i + 1, OUTSIDER1, {sha}));
  // A page of more than 4 pull requests fails.
  const f = fake({prs, slowAbove: 4});
  await maintainerApproval(f.args);
  const pages = f.calls.graphql.map((v) => `${v.cursor} ${v.first}`);
  // Each page starts at the full size.
  assert.deepEqual(
      pages.slice(0, 9),
      ['null 25', 'null 13', 'null 7', 'null 4', '4 25', '4 13', '4 7', '4 4', '8 25']);
  assert.equal(pages.length, 32);
  assert.deepEqual(f.calls.status.map((s) => s.sha), all.toReversed());
  assert.equal(f.warnings.length, 24);
  assert.equal(
      f.warnings[0], 'reads a page of 13 pull request(s) after a failure: timeout');
  assert.deepEqual(f.failed, []);

  // A page of one pull request that fails stops the run.
  const g = fake({prs, slowAbove: 0});
  await assert.rejects(maintainerApproval(g.args), /timeout/);
  assert.deepEqual(
      g.calls.graphql.map((v) => `${v.cursor} ${v.first}`),
      ['null 25', 'null 13', 'null 7', 'null 4', 'null 2', 'null 1']);
  assert.deepEqual(g.calls.status, []);
});

test('each pull request rule can be in a different ruleset', async () => {
  const rule = (parameters) => ({type: 'pull_request', parameters});
  const status = requiredStatuses({context: MASTER, integration_id: APP_ID});
  const none = {
    dismiss_stale_reviews_on_push: false,
    require_last_push_approval: false,
    required_approving_review_count: 0,
  };
  const cases = [
    [
      rule({...none, dismiss_stale_reviews_on_push: true}),
      rule({...none, required_approving_review_count: 2}),
      rule({...none, require_last_push_approval: true}),
    ],
    [rule(none), rule(RULE_PARAMETERS), status],
    [status, rule(RULE_PARAMETERS), rule(none)],
    [
      {type: 'deletion'},
      {type: 'pull_request'},
      {type: 'update'},
      rule(RULE_PARAMETERS),
      requiredStatuses({context: 'ci'}),
      status,
    ],
  ];
  for (const rules of cases) {
    const f = fake({
      prs: [pullRequest(1, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2)})],
      rules: {master: rules},
    });
    await maintainerApproval(f.args);
    assert.deepEqual(
        f.calls.status, [write(HEAD, 'success', description(2, 2))],
        JSON.stringify(rules));
    assert.deepEqual(f.failed, []);
  }
});

test('one base branch without the rules prevents the successful status of a commit', async () => {
  const [a, b, c, d, e, g] = shas(6);
  const two = approvals(ACTIVE1, ACTIVE2);
  const first = 'release/20261101';
  const second = 'release/20261102';
  for (const without of [[first], [second], [first, second]]) {
    const f = fake({
      prs: [
        // No new successful status.
        pullRequest(1, OUTSIDER1, {sha: a, base: first, reviews: two}),
        pullRequest(2, OUTSIDER1, {sha: a, base: second, reviews: two}),
        // A successful status is not kept.
        pullRequest(3, OUTSIDER1, {
          sha: b,
          base: first,
          reviews: two,
          status: status('success', `#3: ${description(2, 2)}`, {context: RELEASE}),
        }),
        pullRequest(4, OUTSIDER1, {sha: b, base: second, reviews: two}),
        // The other family is not affected.
        pullRequest(5, OUTSIDER1, {sha: c, reviews: two}),
        // A commit whose pull requests are all to a base branch with the rules
        // is not affected.
        pullRequest(6, OUTSIDER1, {sha: d, base: first, reviews: two}),
        pullRequest(7, OUTSIDER1, {sha: e, base: second, reviews: two}),
        // A commit without a status gets no successful status. The other
        // family of that commit is not affected.
        pullRequest(8, OUTSIDER1, {sha: g, base: first, status: null, reviews: two}),
        pullRequest(9, OUTSIDER1, {sha: g, base: second, status: null, reviews: two}),
        pullRequest(10, OUTSIDER1, {sha: g, status: null, reviews: two}),
      ],
      rules: Object.fromEntries(without.map((branch) => [branch, []])),
    });
    await maintainerApproval(f.args);
    const release = description(2, 2);
    assert.deepEqual(
        f.calls.status,
        [
          write(b, 'error', ERROR, RELEASE),
          write(g, 'success', description(2, 2)),
          ...(without.includes(second) ? [] : [write(e, 'success', release, RELEASE)]),
          ...(without.includes(first) ? [] : [write(d, 'success', release, RELEASE)]),
          write(c, 'success', description(2, 2)),
        ],
        String(without));
    assert.deepEqual(
        f.errors,
        without.map(
            (branch) => `no ruleset of ${branch} has these rules: ` +
                'dismiss stale approvals, require one approval, ' +
                'require the approval of the most recent push'),
        String(without));
  }
});

test('waits after each write by default', {timeout: 10000}, async () => {
  const f = fake({prs: [pullRequest(1, OUTSIDER1)]});
  const {sleep, ...args} = f.args;
  const start = Date.now();
  await maintainerApproval(args);
  assert.equal(f.calls.status.length, 1);
  assert.ok(Date.now() - start >= 900);
});

test('the author counts only if the author pushed the head commit', async () => {
  const ref = 'refs/heads/feature';
  const lookup = {owner: 'active1', repo: 'gvisor', ref, per_page: 1};
  const counts = description(1, 1, MAINTAINER);
  const doesNotCount = description(1, 2, NOT_PUSHER);
  const cases = [
    {
      name: 'the author pushed',
      activity: activity(HEAD, ACTIVE1),
      state: 'success',
      description: counts,
    },
    {
      name: 'the approver pushed',
      activity: activity(HEAD, ACTIVE2),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'a maintainer who is not the author or an approver pushed',
      activity: activity(HEAD, HIATUS),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'an account that is not a maintainer pushed',
      activity: activity(HEAD, OUTSIDER1),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'a trusted bot pushed',
      activity: activity(HEAD, BOT),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'the newest push is another commit',
      activity: activity(OTHER, ACTIVE1),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'the push has no actor',
      activity: activity(HEAD, null),
      state: 'pending',
      description: doesNotCount,
    },
    {
      name: 'the branch has no activity',
      activity: [],
      state: 'pending',
      description: doesNotCount,
    },
  ];
  for (const c of cases) {
    const f = fake({
      prs: [pullRequest(10, ACTIVE1, {
        reviews: approvals(ACTIVE2),
        headRepository: 'active1/gvisor',
        branch: 'feature',
      })],
      activities: {[`active1/gvisor ${ref}`]: c.activity},
    });
    await maintainerApproval(f.args);
    assert.deepEqual(f.calls.activity, [lookup], c.name);
    assert.deepEqual(f.calls.status, [write(HEAD, c.state, c.description)], c.name);
    assert.deepEqual(f.failed, [], c.name);
  }
});

test('the author counts only if no other account made the last change', async () => {
  const all = shas(12);
  const one = approvals(ACTIVE2);
  const pushed = (author) => ({headRepository: 'x/gvisor', branch: `b${author}`});
  const f = fake({
    prs: [
      // The author made the last change.
      pullRequest(1, ACTIVE1, {
        sha: all[0],
        reviews: one,
        lastChanges: [ACTIVE2, ACTIVE1],
        ...pushed(ACTIVE1),
      }),
      // Another maintainer, an approver, an outsider, a deleted account, or
      // GitHub made it.
      ...[HIATUS, ACTIVE2, OUTSIDER1, null, AUTOMATIC].map(
          (by, i) => pullRequest(2 + i, ACTIVE1, {
            sha: all[1 + i],
            reviews: one,
            lastChanges: [ACTIVE1, by],
            ...pushed(ACTIVE1),
          })),
      // A trusted bot makes no such change.
      pullRequest(7, BOT, {
        sha: all[6],
        reviews: one,
        lastChanges: [ACTIVE2],
        ...pushed(BOT),
      }),
      pullRequest(8, BOT, {
        sha: all[7],
        reviews: one,
        lastChanges: [AUTOMATIC],
        ...pushed(BOT),
      }),
      // Two approvals are sufficient.
      pullRequest(9, ACTIVE1, {
        sha: all[8],
        reviews: approvals(ACTIVE2, HIATUS),
        lastChanges: [ACTIVE2],
      }),
      // The rule does not change for an author who is not a maintainer.
      pullRequest(10, OUTSIDER1, {
        sha: all[9],
        reviews: approvals(ACTIVE1, ACTIVE2),
        lastChanges: [ACTIVE1],
      }),
      pullRequest(11, OUTSIDER1, {
        sha: all[10],
        reviews: one,
        lastChanges: [OUTSIDER1],
      }),
      // The author made the last change after a change of GitHub.
      pullRequest(12, ACTIVE1, {
        sha: all[11],
        reviews: one,
        lastChanges: [AUTOMATIC, ACTIVE1],
        headRepository: 'x/gvisor',
        branch: 'last',
      }),
    ],
    activities: {
      [`x/gvisor refs/heads/b${ACTIVE1}`]: activity(all[0], ACTIVE1),
      [`x/gvisor refs/heads/b${BOT}`]: activity(all[6], BOT),
      'x/gvisor refs/heads/last': activity(all[11], ACTIVE1),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(all[11], 'success', description(1, 1, MAINTAINER)),
    write(all[9], 'success', description(2, 2)),
    write(all[8], 'success', description(2, 2, NOT_BY_AUTHOR)),
    write(all[0], 'success', description(1, 1, MAINTAINER)),
    write(all[10], 'pending', description(1, 2)),
    ...[7, 6, 5, 4, 3, 2, 1].map(
        (i) => write(all[i], 'pending', description(1, 2, NOT_BY_AUTHOR))),
  ]);
  // The pusher is not read when the author does not count.
  assert.equal(f.calls.activity.length, 2);
  assert.deepEqual(f.failed, []);
});

test('a draft pull request is not successful', async () => {
  const [a, b, c, d, e] = shas(5);
  const one = approvals(ACTIVE2);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: a, reviews: two, draft: true}),
      // A successful status is not kept.
      pullRequest(2, ACTIVE1, {
        sha: b,
        reviews: one,
        draft: true,
        status: status('success', description(1, 1, MAINTAINER)),
      }),
      // A draft does not make its head commit successful for another pull
      // request with the same base branch.
      pullRequest(3, ACTIVE1, {sha: c, reviews: one, draft: true}),
      pullRequest(4, OUTSIDER1, {sha: c, reviews: one}),
      // The other pull request can be successful.
      pullRequest(5, ACTIVE1, {sha: d, reviews: one, draft: true}),
      pullRequest(6, OUTSIDER1, {sha: d, reviews: two}),
      // The status is up to date.
      pullRequest(7, OUTSIDER1, {sha: e, draft: true, status: status('pending', DRAFT)}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'pending', DRAFT),
    write(d, 'success', description(2, 2)),
    write(c, 'pending', DRAFT),
    write(a, 'pending', DRAFT),
  ]);
  // The pusher of a draft is not read.
  assert.deepEqual(f.calls.activity, []);
  assert.deepEqual(f.failed, []);
});

test('a draft state that cannot be read is an error', async () => {
  for (const draft of [null, 'false', 0]) {
    const f = fake({
      prs: [
        pullRequest(1, OUTSIDER1, {reviews: approvals(ACTIVE1, ACTIVE2), draft}),
        pullRequest(2, OUTSIDER1, {sha: OTHER}),
      ],
    });
    await maintainerApproval(f.args);
    assert.deepEqual(f.calls.status, [
      write(OTHER, 'pending', description(0, 2)),
      write(HEAD, 'error', ERROR),
    ], String(draft));
    assert.deepEqual(
        f.errors, ['#1: cannot evaluate: cannot read the draft state'], String(draft));
  }
});

test('a pull request without a head repository has no pusher', async () => {
  const f = fake({
    prs: [pullRequest(10, ACTIVE1, {reviews: approvals(ACTIVE2), headRepository: null})],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.activity, []);
  assert.deepEqual(
      f.calls.status, [write(HEAD, 'pending', description(1, 2, NOT_PUSHER))]);
});

test('a trusted bot counts only if the bot pushed the head commit', async () => {
  const key = 'gvisor/gvisor refs/heads/dependabot/x';
  const options = {
    reviews: approvals(ACTIVE1),
    headRepository: 'gvisor/gvisor',
    branch: 'dependabot/x',
  };
  const pushedByBot = fake({
    prs: [pullRequest(10, BOT, options)],
    activities: {[key]: activity(HEAD, BOT)},
  });
  await maintainerApproval(pushedByBot.args);
  assert.deepEqual(
      pushedByBot.calls.status,
      [write(HEAD, 'success', description(1, 1, TRUSTED_BOT))]);

  // The approver, a maintainer who is not an approver, and an account that is
  // not a maintainer.
  // Also a push of another commit, a push without an actor, and a branch
  // without activity.
  const others = [
    ...[ACTIVE1, ACTIVE2, OUTSIDER1].map((pusher) => activity(HEAD, pusher)),
    activity(OTHER, BOT),
    activity(HEAD, null),
    [],
  ];
  for (const other of others) {
    const pushedByOther = fake({
      prs: [pullRequest(10, BOT, options)],
      activities: {[key]: other},
    });
    await maintainerApproval(pushedByOther.args);
    assert.deepEqual(
        pushedByOther.calls.status,
        [write(HEAD, 'pending', description(1, 2, NOT_PUSHER))],
        JSON.stringify(other));
  }
});

test('reads the pusher only if it decides the result', async () => {
  const [a, b, c, d] = shas(4);
  const f = fake({
    prs: [
      // No approval: pending with all pushers.
      pullRequest(1, ACTIVE1, {sha: a}),
      // Two approvals: successful with all pushers.
      pullRequest(2, ACTIVE1, {sha: b, reviews: approvals(ACTIVE2, HIATUS)}),
      // The author is not a maintainer.
      pullRequest(3, OUTSIDER1, {sha: c, reviews: approvals(ACTIVE1, ACTIVE2)}),
      pullRequest(4, OUTSIDER1, {sha: d, reviews: approvals(ACTIVE1)}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.activity, []);
  assert.deepEqual(f.calls.status, [
    write(c, 'success', description(2, 2)),
    write(b, 'success', description(2, 1, UNKNOWN_PUSHER)),
    write(d, 'pending', description(1, 2)),
    write(a, 'pending', description(0, 1, UNKNOWN_PUSHER)),
  ]);
});

test('reads the pusher of each pull request of a commit', async () => {
  const f = fake({
    prs: [
      pullRequest(1, ACTIVE1, {
        reviews: approvals(ACTIVE2),
        headRepository: 'active1/gvisor',
        branch: 'x',
      }),
      pullRequest(2, HIATUS, {
        reviews: approvals(ACTIVE2),
        headRepository: 'hiatus/gvisor',
        branch: 'x',
      }),
    ],
    activities: {
      'active1/gvisor refs/heads/x': activity(HEAD, ACTIVE2),
      'hiatus/gvisor refs/heads/x': activity(HEAD, HIATUS),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.activity.map((p) => p.owner), ['active1', 'hiatus']);
  assert.deepEqual(
      f.calls.status,
      [write(HEAD, 'success', description(1, 1, MAINTAINER))]);
});

test('each pull request of a commit has its own author', async () => {
  const [a, b, c, d] = shas(4);
  const one = approvals(ACTIVE2);
  const f = fake({
    prs: [
      // The author of another pull request of the commit is a maintainer.
      // That does not give an agreement to this pull request.
      pullRequest(1, ACTIVE1, {sha: a}),
      pullRequest(2, OUTSIDER1, {sha: a, reviews: one}),
      pullRequest(3, OUTSIDER1, {sha: b, reviews: one}),
      pullRequest(4, ACTIVE1, {sha: b}),
      // That maintainer pushed the head commit to the branch of this pull
      // request.
      pullRequest(5, ACTIVE1, {sha: c}),
      pullRequest(6, OUTSIDER1, {sha: c, reviews: one}),
      // The author of another pull request of the commit is not a maintainer.
      // That does not remove the agreement of the author of this one.
      pullRequest(7, ACTIVE1, {sha: d, reviews: one}),
      pullRequest(8, OUTSIDER1, {sha: d}),
    ],
    activities: {
      'outsider/gvisor refs/heads/branch2': activity(a, OUTSIDER1),
      'outsider/gvisor refs/heads/branch3': activity(b, OUTSIDER1),
      'outsider/gvisor refs/heads/branch6': activity(c, ACTIVE1),
      'outsider/gvisor refs/heads/branch7': activity(d, ACTIVE1),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.activity.map((p) => p.ref), ['refs/heads/branch7']);
  assert.deepEqual(f.calls.status, [
    write(d, 'success', description(1, 1, MAINTAINER)),
    // The status is that of the pull request with the most approvals.
    write(c, 'pending', description(1, 2)),
    write(b, 'pending', description(1, 2)),
    write(a, 'pending', description(1, 2)),
  ]);
  assert.deepEqual(f.failed, []);
});

test('each pull request of a commit has its own last change', async () => {
  const [a, b, c, d] = shas(4);
  const one = approvals(ACTIVE2);
  const f = fake({
    prs: [
      // Another account made the last change of the pull request of the
      // maintainer. The other pull request of the commit has no such change.
      // That does not give the agreement of the author.
      pullRequest(1, OUTSIDER1, {sha: a}),
      pullRequest(2, ACTIVE1, {sha: a, reviews: one, lastChanges: [ACTIVE2]}),
      pullRequest(3, ACTIVE1, {sha: b, reviews: one, lastChanges: [ACTIVE2]}),
      pullRequest(4, OUTSIDER1, {sha: b}),
      // Another account made the last change of the other pull request of
      // the commit. That does not remove the agreement of the author of this
      // one.
      pullRequest(5, OUTSIDER1, {sha: c, lastChanges: [ACTIVE2]}),
      pullRequest(6, ACTIVE1, {sha: c, reviews: one}),
      pullRequest(7, ACTIVE1, {sha: d, reviews: one}),
      pullRequest(8, OUTSIDER1, {sha: d, lastChanges: [ACTIVE2]}),
    ],
    activities: {
      'outsider/gvisor refs/heads/branch2': activity(a, ACTIVE1),
      'outsider/gvisor refs/heads/branch3': activity(b, ACTIVE1),
      'outsider/gvisor refs/heads/branch6': activity(c, ACTIVE1),
      'outsider/gvisor refs/heads/branch7': activity(d, ACTIVE1),
    },
  });
  await maintainerApproval(f.args);
  assert.deepEqual(
      f.calls.activity.map((p) => p.ref),
      ['refs/heads/branch6', 'refs/heads/branch7']);
  assert.deepEqual(f.calls.status, [
    write(d, 'success', description(1, 1, MAINTAINER)),
    write(c, 'success', description(1, 1, MAINTAINER)),
    write(b, 'pending', description(1, 2, NOT_BY_AUTHOR)),
    write(a, 'pending', description(1, 2, NOT_BY_AUTHOR)),
  ]);
  assert.deepEqual(f.failed, []);
});

test('each pull request of a commit has its own base change', async () => {
  const [a, b] = shas(2);
  // The approvals are older than the change of the base branch.
  const two = approvals(ACTIVE1, ACTIVE2);
  const changed = {reviews: two, baseChanges: ['2026-03-01T00:00:00Z']};
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: a, ...changed}),
      pullRequest(2, OUTSIDER1, {sha: a, reviews: two}),
      pullRequest(3, OUTSIDER1, {sha: b, reviews: two}),
      pullRequest(4, OUTSIDER1, {sha: b, ...changed}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'success', description(2, 2)),
    write(a, 'success', description(2, 2)),
  ]);
});

test('replaces a successful status that no open pull request needs', async () => {
  const [a, b, c, d, e, g, h, i, j, k, l, m, n] = shas(13);
  const success = status('success', description(2, 2));
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const options = {
    prs: [
      // The base branch is no longer in a family.
      pullRequest(1, OUTSIDER1, {sha: a, base: 'feature', status: success}),
      // The base branch is now in another family.
      pullRequest(2, OUTSIDER1, {
        sha: b,
        status: status('success', description(2, 2), {context: RELEASE}),
      }),
      // A status of the app that is not successful.
      pullRequest(3, OUTSIDER1, {
        sha: c,
        base: 'feature',
        status: status('pending', description(0, 2)),
      }),
      // A status that the app did not set can hide a successful status.
      pullRequest(4, OUTSIDER1, {
        sha: d,
        base: 'feature',
        status: status('pending', description(0, 2), other),
      }),
      // An open pull request needs the status of this commit.
      pullRequest(5, OUTSIDER1, {
        sha: e,
        reviews: approvals(ACTIVE1, ACTIVE2),
        status: success,
      }),
      // A new successful status comes after the replacements.
      pullRequest(6, OUTSIDER1, {sha: i, reviews: approvals(ACTIVE1, ACTIVE2)}),
    ],
    closed: [
      pullRequest(7, OUTSIDER1, {sha: g, status: success}),
      // A second closed pull request with the same head commit.
      pullRequest(8, OUTSIDER1, {sha: g, status: success}),
      pullRequest(9, OUTSIDER1, {sha: e, status: success}),
      pullRequest(10, OUTSIDER1, {sha: h, status: status('pending', NOT_NEEDED)}),
      // A status without a creator is not a status of the app.
      pullRequest(15, OUTSIDER1, {
        sha: m,
        status: status('pending', 'x', {creator: null}),
      }),
      // The response does not have the head commit.
      pullRequest(11, OUTSIDER1, {commits: [{oid: OTHER, status: success}]}),
      // A pull request without commits. The statuses of the pull requests
      // after it are read.
      pullRequest(17, OUTSIDER1, {commits: []}),
      // A status of the other family.
      pullRequest(12, OUTSIDER1, {
        sha: j,
        status: status('success', description(2, 2), {context: RELEASE}),
      }),
      // A status that the app did not set can hide a successful status.
      pullRequest(13, OUTSIDER1, {sha: k, status: status('pending', 'x', other)}),
      // An error status of the app stays.
      pullRequest(14, OUTSIDER1, {sha: l, status: status('error', ERROR)}),
      // A commit with successful statuses of two families.
      pullRequest(16, OUTSIDER1, {
        sha: n,
        status: {
          ...success,
          ...status('success', description(2, 2), {context: RELEASE}),
        },
      }),
    ],
  };
  const replacements = [
    write(a, 'pending', NOT_NEEDED),
    write(b, 'pending', NOT_NEEDED, RELEASE),
    write(g, 'pending', NOT_NEEDED),
    write(j, 'pending', NOT_NEEDED, RELEASE),
    write(n, 'pending', NOT_NEEDED),
    write(n, 'pending', NOT_NEEDED, RELEASE),
    // The statuses that the app did not set come after the successful
    // statuses of the app.
    write(d, 'pending', NOT_NEEDED),
    write(m, 'pending', NOT_NEEDED),
    write(k, 'pending', NOT_NEEDED),
  ];
  const f = fake(options);
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    ...replacements,
    write(i, 'success', description(2, 2)),
  ]);
  assert.deepEqual(f.failed, []);

  // The replacements do not need the rosters.
  const withoutRosters = fake(options);
  await maintainerApproval({
    ...withoutRosters.args,
    load: () => {
      throw new Error('yq failed');
    },
  });
  assert.deepEqual(
      withoutRosters.calls.status, [write(e, 'error', ERROR), ...replacements]);

  // The replacements do not need the rules of the base branches.
  const withoutRules = fake({...options, rules: {master: []}});
  await maintainerApproval(withoutRules.args);
  assert.deepEqual(
      withoutRules.calls.status, [write(e, 'error', ERROR), ...replacements]);
  // If the rules cannot be read, the successful status that is correct stays.
  const unreadRules = fake({...options, fail: ['rules']});
  await maintainerApproval(unreadRules.args);
  assert.deepEqual(unreadRules.calls.status, replacements);
});

test('a merged pull request keeps the status of the family of its base branch', async () => {
  const [a, b, c, d, e, g, h, i] = shas(8);
  const success = status('success', description(2, 2));
  const both = {
    ...success,
    ...status('success', description(2, 2), {context: RELEASE}),
  };
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const f = fake({
    closed: [
      pullRequest(1, OUTSIDER1, {sha: a, status: success, merged: true}),
      // A pull request that is closed and not merged.
      pullRequest(2, OUTSIDER1, {sha: b, status: success}),
      // The status of the other family does not stay.
      pullRequest(3, OUTSIDER1, {sha: c, status: both, merged: true}),
      // A release branch: the status of the release family stays.
      pullRequest(4, OUTSIDER1, {
        sha: d,
        base: 'release/20261101',
        status: both,
        merged: true,
      }),
      // The base branch is in no family.
      pullRequest(5, OUTSIDER1, {sha: e, base: 'feature', status: success, merged: true}),
      // A status that the app did not set stays too.
      pullRequest(6, OUTSIDER1, {
        sha: g,
        status: status('pending', 'x', other),
        merged: true,
      }),
      // A closed pull request has the head commit of a merged one.
      pullRequest(7, OUTSIDER1, {sha: h, status: success, merged: true}),
      pullRequest(8, OUTSIDER1, {sha: h, status: success}),
      // The merged state cannot be read.
      pullRequest(9, OUTSIDER1, {sha: i, status: success, merged: null}),
    ],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'pending', NOT_NEEDED),
    write(c, 'pending', NOT_NEEDED, RELEASE),
    write(d, 'pending', NOT_NEEDED),
    write(e, 'pending', NOT_NEEDED),
    write(h, 'pending', NOT_NEEDED),
    write(i, 'pending', NOT_NEEDED),
  ]);
  assert.deepEqual(f.failed, []);
});

test('reads the closed pull requests that have a recent update', async () => {
  const success = status('success', description(2, 2));
  // The pull requests with these times of the last update, newest first.
  const closedAt = (times) => {
    const all = shas(times.length);
    return times.map(
        (updatedAt, i) => pullRequest(
            1000 + i, OUTSIDER1, {sha: all[i], status: success, updatedAt}));
  };
  const range = (length, time) => Array.from({length}, (_, i) => time(i));
  const cases = [
    {
      name: 'the update is not older than 48 hours',
      closed: closedAt(range(160, (i) => hoursAgo(i / 2))),
      replaced: 97,
      cursors: [null, '50'],
    },
    {
      name: 'at least the first page',
      closed: closedAt(range(60, () => hoursAgo(100))),
      replaced: 50,
      cursors: [null],
    },
    {
      name: 'the first page has all pull requests',
      closed: closedAt(range(50, () => hoursAgo(1))),
      replaced: 50,
      cursors: [null],
    },
    {
      name: 'no closed pull request',
      closed: [],
      replaced: 0,
      cursors: [null],
    },
    {
      name: 'a time that cannot be read is not old',
      closed: closedAt([
        ...range(55, () => hoursAgo(1)),
        null,
        hoursAgo(49),
        'x',
        hoursAgo(49),
        hoursAgo(1),
      ]),
      // The old pull requests of the second page.
      skipped: [56, 58],
      replaced: 58,
      cursors: [null, '50'],
    },
    {
      name: 'a limited number of pages',
      closed: closedAt(range(600, () => hoursAgo(1))),
      replaced: 500,
      cursors: [null, '50', '100', '150', '200', '250', '300', '350', '400', '450'],
      warnings: ['only the 500 closed pull requests with the newest updates are read'],
    },
  ];
  for (const c of cases) {
    const f = fake({closed: c.closed});
    await maintainerApproval(f.args);
    const skipped = c.skipped || [];
    const want = c.closed.filter((pr, i) => !skipped.includes(i))
                     .slice(0, c.replaced)
                     .map((pr) => write(pr.sha, 'pending', NOT_NEEDED));
    assert.equal(want.length, c.replaced, c.name);
    assert.deepEqual(f.calls.status, want, c.name);
    assert.deepEqual(f.calls.closed.map((v) => v.cursor), c.cursors, c.name);
    assert.deepEqual(f.warnings, c.warnings || [], c.name);
    assert.deepEqual(f.failed, [], c.name);
  }
});

test('uses the clock by default', async () => {
  const success = status('success', description(2, 2));
  const all = shas(52);
  const current = new Date().toISOString();
  const f = fake({
    closed: all.map(
        (sha, i) => pullRequest(1000 + i, OUTSIDER1, {
          sha,
          status: success,
          // The time of the fake is older than 48 hours.
          updatedAt: i === 51 ? hoursAgo(0) : current,
        })),
  });
  const {now, ...args} = f.args;
  await maintainerApproval(args);
  assert.deepEqual(
      f.calls.status,
      all.slice(0, 51).map((sha) => write(sha, 'pending', NOT_NEEDED)));
});

test('the run continues after a failure to read the closed pull requests', async () => {
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1),
      // The statuses of the open pull requests are replaced.
      pullRequest(2, OUTSIDER1, {
        sha: OTHER,
        base: 'feature',
        status: status('success', description(2, 2)),
      }),
    ],
    fail: ['closed'],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(OTHER, 'pending', NOT_NEEDED),
    write(HEAD, 'pending', description(0, 2)),
  ]);
  assert.deepEqual(
      f.errors, ['cannot read the closed pull requests: closed failed']);
  assert.deepEqual(f.failed, ['1 failure(s)']);
});

test('a failed evaluation sets an error status and continues', async () => {
  const [a, b, c] = shas(3);
  const options = {
    reviews: approvals(ACTIVE2),
    headRepository: 'active1/gvisor',
    branch: 'x',
  };
  const f = fake({
    prs: [
      pullRequest(1, ACTIVE1, {...options, sha: a}),
      pullRequest(2, OUTSIDER1, {sha: b}),
      // An error status that is up to date is not set again.
      pullRequest(3, ACTIVE1, {...options, sha: c, status: status('error', ERROR)}),
    ],
    fail: ['activity'],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(b, 'pending', description(0, 2)),
    write(a, 'error', ERROR),
  ]);
  assert.deepEqual(f.errors, [
    '#1: cannot evaluate: activity failed',
    '#3: cannot evaluate: activity failed',
  ]);
  assert.deepEqual(f.failed, ['2 failure(s)']);
});

test('a failure to read older reviews sets an error status', async () => {
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {
        reviews: Array.from({length: 101}, () => review(ACTIVE1, 'APPROVED')),
        status: status('success', description(2, 2)),
      }),
      pullRequest(2, OUTSIDER1, {sha: OTHER}),
    ],
    fail: ['reviews'],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(HEAD, 'error', ERROR),
    write(OTHER, 'pending', description(0, 2)),
  ]);
  assert.deepEqual(f.errors, ['#1: cannot evaluate: reviews failed']);
  assert.deepEqual(f.failed, ['1 failure(s)']);
});

test('a pull request that cannot be read prevents new successful statuses of a family with more than one branch', async () => {
  const all = shas(60);
  const two = approvals(ACTIVE1, ACTIVE2);
  const release = 'release/20261101';
  const f = fake({
    prs: [
      pullRequest(1, OUTSIDER1, {sha: all[0]}),
      pullRequest(2, OUTSIDER1, {sha: all[1], reviews: two}),
      pullRequest(3, OUTSIDER1, {sha: all[2], base: release, reviews: two}),
      // A successful status that stays successful.
      pullRequest(4, OUTSIDER1, {
        sha: all[3],
        base: release,
        reviews: two,
        status: status('success', description(3, 2), {context: RELEASE}),
      }),
      // A successful status that is out of date.
      pullRequest(5, OUTSIDER1, {
        sha: all[4],
        base: release,
        status: status('success', description(2, 2), {context: RELEASE}),
      }),
      // A status that is not known.
      pullRequest(6, OUTSIDER1, {
        sha: all[5],
        base: release,
        reviews: two,
        commits: [{oid: OTHER}],
      }),
      ...all.slice(6, 56).map(
          (sha, i) => pullRequest(7 + i, OUTSIDER1, {sha, base: 'feature'})),
      // Successful statuses on the head commits of open pull requests that no
      // open pull request that can be read needs: the base branch is in no
      // family, or it is in the other family.
      pullRequest(57, OUTSIDER1, {
        sha: all[56],
        status: {
          ...status('pending', description(0, 2)),
          ...status('success', 'x', {context: RELEASE}),
        },
      }),
      pullRequest(58, OUTSIDER1, {
        sha: all[57],
        base: 'feature',
        status: status('success', 'x'),
      }),
      // A commit without a status.
      pullRequest(59, OUTSIDER1, {
        sha: all[58],
        base: release,
        reviews: two,
        status: null,
      }),
      // A pull request of another page of the response.
      pullRequest(60, OUTSIDER1, {sha: all[59], base: release, reviews: two}),
    ],
    closed: [
      pullRequest(70, OUTSIDER1, {sha: OTHER, status: status('success', 'x')}),
    ],
    unreadable: [1],
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(all[4], 'pending', description(0, 2), RELEASE),
    write(all[3], 'success', description(2, 2), RELEASE),
    // The master family has one branch.
    write(all[1], 'success', description(2, 2)),
    // The pull request that cannot be read can need the status of the closed
    // pull request, or the statuses of the open pull requests that no other
    // pull request needs: they are not replaced.
  ]);
  assert.deepEqual(f.errors, [
    'incomplete response: a field failed',
    'cannot read the pull request after #0',
    '#6: cannot read the status of the head commit',
  ]);
  assert.deepEqual(f.failed, ['3 failure(s)']);
});

test('a pull request with an error in its data gets an error status', async () => {
  const changes = [
    (node) => {
      node.reviews = null;
    },
    (node) => {
      node.reviews.nodes = [null];
    },
    (node) => {
      node.baseChanges = {nodes: [null]};
    },
    (node) => {
      node.baseChanges = null;
    },
    (node) => {
      node.commits = null;
    },
    (node) => {
      node.author = null;
    },
    () => {},
  ];
  for (const change of changes) {
    const f = fake({
      prs: [
        pullRequest(1, OUTSIDER1, {
          reviews: approvals(ACTIVE1, ACTIVE2),
          status: status('success', description(2, 2)),
          baseChanges: ['2026-01-01T00:00:00Z'],
        }),
        pullRequest(2, OUTSIDER1, {sha: OTHER}),
        // The data of a pull request whose base branch is in no family is not
        // necessary.
        pullRequest(3, OUTSIDER1, {sha: 'c'.repeat(40), base: 'feature'}),
      ],
      partial: {1: change, 3: change},
    });
    await maintainerApproval(f.args);
    assert.deepEqual(
        f.calls.status,
        [write(HEAD, 'error', ERROR), write(OTHER, 'pending', description(0, 2))],
        String(change));
    assert.deepEqual(
        f.errors,
        ['incomplete response: a field failed', '#1: cannot evaluate: a field failed'],
        String(change));
    assert.deepEqual(f.failed, ['2 failure(s)']);
  }

  // An error status that is up to date is not set again.
  const again = fake({
    prs: [pullRequest(1, OUTSIDER1, {status: status('error', ERROR)})],
    partial: {1: () => {}},
  });
  await maintainerApproval(again.args);
  assert.deepEqual(again.calls.status, []);
});

test('an error is in the pull request at the index of its page', async () => {
  const all = shas(60);
  const f = fake({
    prs: all.map(
        (sha, i) => pullRequest(
            i + 1, OUTSIDER1, {sha, status: status('pending', description(0, 2))})),
    partial: {2: () => {}, 53: () => {}},
  });
  await maintainerApproval(f.args);
  assert.deepEqual(
      f.calls.status,
      [write(all[52], 'error', ERROR), write(all[1], 'error', ERROR)]);
});

test('a base change that cannot be read is an error', async () => {
  for (const item of [null, {}, {createdAt: null}, {createdAt: 0}, {createdAt: 1}]) {
    const f = fake({
      prs: [pullRequest(1, OUTSIDER1, {
        reviews: approvals(ACTIVE1, ACTIVE2),
        baseChanges: ['2026-03-01T00:00:00Z'],
      })],
    });
    const {graphql} = f.args.github;
    f.args.github.graphql = async (query, variables) => {
      const data = await graphql(query, variables);
      for (const node of data.repository.pullRequests?.nodes || []) {
        if (node.baseChanges) {
          node.baseChanges.nodes = [item];
        }
      }
      return data;
    };
    await maintainerApproval(f.args);
    assert.deepEqual(f.calls.status, [write(HEAD, 'error', ERROR)], String(item));
    assert.deepEqual(
        f.errors,
        ['#1: cannot evaluate: cannot read the change of the base branch']);
  }
});

test('a last change that cannot be read is not a change of the author', async () => {
  // An item without data, an item without an actor, and an actor that is not
  // a user or a bot.
  for (const item of [null, {}, {actor: null}, {actor: {}}]) {
    const f = fake({
      prs: [pullRequest(1, ACTIVE1, {
        reviews: approvals(ACTIVE2),
        lastChanges: [ACTIVE1],
      })],
      activities: {'outsider/gvisor refs/heads/branch1': activity(HEAD, ACTIVE1)},
    });
    const {graphql} = f.args.github;
    f.args.github.graphql = async (query, variables) => {
      const data = await graphql(query, variables);
      for (const node of data.repository.pullRequests?.nodes || []) {
        if (node.lastChange) {
          node.lastChange.nodes = [item];
        }
      }
      return data;
    };
    await maintainerApproval(f.args);
    assert.deepEqual(
        f.calls.status,
        [write(HEAD, 'pending', description(1, 2, NOT_BY_AUTHOR))],
        JSON.stringify(item));
    assert.deepEqual(f.calls.activity, []);
  }
});

test('a pull request with an error counts for its base branch only', async () => {
  const [a, b] = shas(2);
  const two = approvals(ACTIVE1, ACTIVE2);
  const f = fake({
    prs: [
      // Another base branch of the family.
      pullRequest(10, OUTSIDER1, {sha: a, base: 'release/20261101', reviews: two}),
      pullRequest(11, OUTSIDER1, {sha: a, base: 'release/20261102'}),
      // The same base branch: the successful pull request is sufficient.
      pullRequest(20, OUTSIDER1, {sha: b, reviews: two}),
      pullRequest(21, OUTSIDER1, {sha: b}),
      // The pull request with the error is first.
      pullRequest(30, OUTSIDER1, {sha: OTHER}),
      pullRequest(31, OUTSIDER1, {sha: OTHER, reviews: two}),
      // The error does not prevent the new successful status of another
      // commit.
      pullRequest(40, OUTSIDER1, {sha: HEAD, base: 'release/20261101', reviews: two}),
    ],
    partial: {11: () => {}, 21: () => {}, 30: () => {}},
  });
  await maintainerApproval(f.args);
  assert.deepEqual(f.calls.status, [
    write(HEAD, 'success', description(2, 2), RELEASE),
    write(OTHER, 'success', description(2, 2)),
    write(b, 'success', description(2, 2)),
    write(a, 'error', `#11: ${ERROR}`, RELEASE),
  ]);
  assert.deepEqual(f.failed, ['4 failure(s)']);
});

test('a pull request without a required field counts as not read', async () => {
  for (const field of ['headRefOid', 'baseRefName']) {
    const [a, b] = shas(2);
    const f = fake({
      prs: [
        pullRequest(1, OUTSIDER1),
        pullRequest(2, OUTSIDER1, {sha: OTHER}),
        // No new successful status of a family with more than one branch.
        pullRequest(3, OUTSIDER1, {
          sha: a,
          base: 'release/20261101',
          reviews: approvals(ACTIVE1, ACTIVE2),
        }),
      ],
      // The status of the closed pull request is not replaced.
      closed: [pullRequest(4, OUTSIDER1, {sha: b, status: status('success', 'x')})],
      partial: {
        2: (node) => {
          node[field] = null;
        },
      },
    });
    await maintainerApproval(f.args);
    assert.deepEqual(f.calls.status, [write(HEAD, 'pending', description(0, 2))]);
    assert.deepEqual(
        f.errors,
        ['incomplete response: a field failed', 'cannot read the pull request after #1']);
  }
});

test('an error that is not in a pull request stops the run', async () => {
  const paths = [
    true,
    'no errors',
    [],
    ['repository'],
    ['repository', 'pullRequests', 'pageInfo'],
    ['repository', 'pullRequests', 'nodes'],
    ['repository', 'pullRequests', 'nodes', 'x'],
    ['repository', 'pullRequests', 'edges', 0],
    ['repository', 'other', 'nodes', 0],
    ['other', 'pullRequests', 'nodes', 0],
  ];
  for (const unattributed of paths) {
    for (const partial of [{}, {1: () => {}}]) {
      if (unattributed === 'no errors' && Object.keys(partial).length > 0) {
        // The response has an error of a pull request, thus its list of
        // errors is not empty.
        continue;
      }
      const f = fake({prs: [pullRequest(1, OUTSIDER1)], unattributed, partial});
      await assert.rejects(
          maintainerApproval(f.args), /a field failed/, String(unattributed));
      assert.deepEqual(f.calls.status, []);
    }
  }
});

test('the run continues after a failure to set a status', async () => {
  // A status that GitHub rejects, a server error, and an error without a
  // response.
  for (const code of [422, 500, undefined]) {
    const f = fake({
      prs: [pullRequest(1, OUTSIDER1, {sha: OTHER}), pullRequest(2, OUTSIDER1)],
      fail: [`status:${HEAD}`],
      writeError: Object.assign(new Error('too many statuses'), {status: code}),
    });
    const result = await maintainerApproval(f.args);
    assert.deepEqual(f.calls.status.map((s) => s.sha), [HEAD, OTHER], String(code));
    assert.deepEqual(f.calls.sleep, [1000, 1000]);
    assert.deepEqual(
        f.errors, [`${HEAD} master: cannot set the status: too many statuses`]);
    assert.deepEqual(f.failed, ['1 failure(s)']);
    // The status that was not set does not count.
    assert.deepEqual(result, {commits: 2, written: 1});
  }
});

test('a refused write stops the writes', async () => {
  for (const code of [403, 429]) {
    const f = fake({
      prs: [pullRequest(1, OUTSIDER1, {sha: OTHER}), pullRequest(2, OUTSIDER1)],
      fail: ['status'],
      writeError: Object.assign(new Error('rate limit'), {status: code}),
    });
    await maintainerApproval(f.args);
    assert.deepEqual(f.calls.status.map((s) => s.sha), [HEAD]);
    assert.deepEqual(f.calls.sleep, []);
    // The run sends no more requests.
    assert.deepEqual(f.calls.accounts, []);
    assert.deepEqual(f.failed, ['1 failure(s)']);
  }
});

test('without valid rosters, no status stays successful', async () => {
  const [a, b, c, d, e, g, h] = shas(7);
  const success = status('success', description(2, 2));
  const other = {creator: {__typename: 'Bot', login: 'github-actions'}};
  const prs = [
    pullRequest(1, OUTSIDER1, {
      sha: a,
      reviews: approvals(ACTIVE1, ACTIVE2),
      status: success,
    }),
    // The author is a maintainer: the roster of the bots is not necessary for
    // the result, but it must be valid.
    pullRequest(2, ACTIVE1, {
      sha: b,
      reviews: approvals(ACTIVE2, HIATUS),
      status: status('success', description(2, 1, UNKNOWN_PUSHER)),
    }),
    // A status that is not known can be successful.
    pullRequest(3, OUTSIDER1, {sha: c, commits: [{oid: OTHER}]}),
    // The other commits get no status.
    pullRequest(4, OUTSIDER1, {sha: d, reviews: approvals(ACTIVE1, ACTIVE2)}),
    pullRequest(5, OUTSIDER1, {sha: e, status: status('pending', 'x')}),
    // A status that the app did not set can hide a successful status.
    pullRequest(6, OUTSIDER1, {sha: g, status: status('pending', 'x', other)}),
    // A commit without a status gets no successful status. The author is a
    // maintainer.
    pullRequest(7, ACTIVE1, {
      sha: h,
      status: null,
      reviews: approvals(ACTIVE2, HIATUS),
    }),
  ];
  const loaders = [
    () => ({maintainers: [{github_id: 1, status: 'RETIRED'}], bots: []}),
    () => {
      throw new Error('yq failed');
    },
    (file) => file.endsWith('bots.yaml') ? {} : ROSTERS['governance/maintainers.yaml'],
  ];
  for (const load of loaders) {
    const f = fake({prs});
    await maintainerApproval({...f.args, load});
    assert.deepEqual(f.calls.status, [
      // The successful statuses of the app come first.
      write(b, 'error', ERROR),
      write(a, 'error', ERROR),
      write(g, 'error', ERROR),
      write(c, 'error', ERROR),
    ]);
    assert.equal(f.errors.length, 2);
    assert.match(f.errors[1], /^cannot read the rosters: /);
    assert.deepEqual(f.failed, ['2 failure(s)']);
  }
});

test('a failure to read the pull requests sets no status', async () => {
  const f = fake({prs: [pullRequest(1, OUTSIDER1)], fail: ['graphql']});
  await assert.rejects(maintainerApproval(f.args), /graphql failed/);
  assert.deepEqual(f.calls.status, []);
});

test('the slug of the app is necessary', async () => {
  for (const appSlug of [undefined, '']) {
    const f = fake({prs: [pullRequest(1, OUTSIDER1)]});
    await assert.rejects(maintainerApproval({...f.args, appSlug}), /slug/);
    assert.deepEqual(f.calls.graphql, []);
  }
});

test('uses the rosters of the workspace, and gives yq no credentials', async (t) => {
  // A yq that prints fixtures, and that fails if it has the credential.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'maintainer-approval-'));
  const saved = {
    cwd: process.cwd(),
    PATH: process.env.PATH,
    GITHUB_WORKSPACE: process.env.GITHUB_WORKSPACE,
    TEST_CREDENTIAL: process.env.TEST_CREDENTIAL,
  };
  t.after(() => {
    process.chdir(saved.cwd);
    for (const name of ['PATH', 'GITHUB_WORKSPACE', 'TEST_CREDENTIAL']) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    }
    fs.rmSync(dir, {recursive: true});
  });
  fs.mkdirSync(path.join(dir, 'bin'));
  fs.mkdirSync(path.join(dir, 'governance'));
  fs.writeFileSync(
      path.join(dir, 'bin', 'yq'),
      '#!/bin/sh\n' +
          'if [ -n "${TEST_CREDENTIAL}" ]; then echo credential >&2; exit 1; fi\n' +
          '[ "$1" = --output-format=json ] && [ "$2" = . ] || exit 2\n' +
          'exec cat "$3.json"\n',
      {mode: 0o755});
  for (const [name, roster] of Object.entries(ROSTERS)) {
    fs.writeFileSync(path.join(dir, `${name}.json`), JSON.stringify(roster));
  }
  process.env.PATH = `${path.join(dir, 'bin')}:${saved.PATH}`;
  process.env.GITHUB_WORKSPACE = dir;
  process.env.TEST_CREDENTIAL = 'secret';
  process.chdir('/');

  const f = fake({
    prs: [
      pullRequest(1, EMERITUS, {reviews: approvals(ACTIVE1, EMERITUS)}),
      pullRequest(2, BOT, {sha: OTHER}),
    ],
  });
  const {load, ...args} = f.args;
  await maintainerApproval(args);
  assert.deepEqual(f.errors, []);
  assert.deepEqual(f.calls.status, [
    write(OTHER, 'pending', description(0, 1, UNKNOWN_PUSHER)),
    write(HEAD, 'pending', description(1, 2)),
  ]);
});

test('the rosters of the repository are valid', () => {
  const maintainers =
      maintainerIDs(loadYAML(path.join(REPO_ROOT, 'governance/maintainers.yaml')));
  const bots = botIDs(loadYAML(path.join(REPO_ROOT, 'governance/bots.yaml')));
  assert.ok(maintainers.size >= 2, 'the rule needs two maintainers');
  for (const id of bots) {
    assert.ok(!maintainers.has(id), `${id} is a maintainer and a bot`);
  }
});

test('the workflows agree with each other and with the script', () => {
  const workflow = (name) => loadYAML(path.join(__dirname, name));
  const evaluator = workflow('maintainer_approval.yml');
  const trigger = workflow('maintainer_approval_trigger.yml');
  const tests = workflow('maintainer_approval_test.yml');
  // Each run of the trigger workflow starts an evaluation: the event has no
  // filter of branches. The schedule is for the pull requests whose trigger
  // workflow does not run. No pull request event starts the evaluation
  // workflow: GitHub runs the workflow of such an event from the pull request.
  assert.deepEqual(
      Object.keys(evaluator.on).toSorted(),
      ['push', 'schedule', 'workflow_dispatch', 'workflow_run']);
  assert.deepEqual(
      evaluator.on.workflow_run, {workflows: [trigger.name], types: ['completed']});
  assert.deepEqual(evaluator.on.schedule, [{cron: '7,22,37,52 * * * *'}]);
  // The events that can change a result, for all pull requests: no filter of
  // branches or paths, and no condition other than the repository.
  assert.deepEqual(
      Object.keys(trigger.on).toSorted(), ['pull_request', 'pull_request_review']);
  assert.deepEqual(Object.keys(trigger.on.pull_request), ['types']);
  assert.deepEqual(Object.keys(trigger.on.pull_request_review), ['types']);
  assert.deepEqual(
      trigger.on.pull_request.types.toSorted(),
      [
        'closed',
        'converted_to_draft',
        'edited',
        'opened',
        'ready_for_review',
        'reopened',
        'synchronize',
      ]);
  assert.deepEqual(
      trigger.on.pull_request_review.types.toSorted(), ['dismissed', 'submitted']);
  assert.deepEqual(Object.keys(trigger.jobs), ['notify']);
  assert.equal(trigger.jobs.notify.if, 'github.repository == \'gvisor/gvisor\'');
  // The job does nothing: it has no other setting, and its step is
  // successful and uses no content of the pull request.
  assert.deepEqual(
      Object.keys(trigger.jobs.notify).toSorted(),
      ['if', 'runs-on', 'steps', 'timeout-minutes']);
  assert.equal(trigger.jobs.notify['runs-on'], 'ubuntu-latest');
  assert.deepEqual(trigger.jobs.notify.steps, [{name: 'Do nothing', run: 'true'}]);
  // The trigger workflow has no permissions, and it is not in the concurrency
  // group of the evaluation.
  assert.deepEqual(trigger.permissions, {});
  assert.equal(trigger.jobs.notify.permissions, undefined);
  assert.equal(trigger.concurrency, undefined);
  assert.equal(trigger.jobs.notify.concurrency, undefined);
  assert.deepEqual(
      evaluator.on.push.paths.toSorted(),
      [
        '.github/workflows/maintainer_approval.js',
        'governance/bots.yaml',
        'governance/maintainers.yaml',
      ]);
  assert.deepEqual(evaluator.on.push.branches, ['master']);
  // The tests examine each change of the script, of the workflows and of the
  // rosters.
  for (const event of [tests.on.pull_request, tests.on.push]) {
    assert.deepEqual(
        event.paths.toSorted(),
        [
          '.github/workflows/maintainer_approval*',
          'governance/bots.yaml',
          'governance/maintainers.yaml',
        ]);
  }
  assert.deepEqual(tests.on.push.branches, ['master']);
  // No other event runs the tests, and no filter of branches or types stops
  // them for a pull request.
  assert.deepEqual(Object.keys(tests.on).toSorted(), ['pull_request', 'push']);
  assert.deepEqual(Object.keys(tests.on.pull_request), ['paths']);
  // The tests are not in the concurrency group of the evaluation.
  assert.notEqual(tests.concurrency.group, evaluator.concurrency.group);
  // The job that runs the tests of a pull request has a token that can only
  // read. The dry run reads the pull requests of this repository only.
  assert.deepEqual(tests.permissions, {contents: 'read'});
  assert.equal(tests.jobs.test.permissions, undefined);
  assert.equal(tests.jobs['dry-run'].if, 'github.repository == \'gvisor/gvisor\'');
  const jobs = [evaluator.jobs.evaluate, tests.jobs.test, tests.jobs['dry-run']];
  for (const job of jobs) {
    // The files that the script reads, and the image whose yq it uses.
    const checkout = job.steps.find((s) => s.uses?.startsWith('actions/checkout@'));
    assert.deepEqual(
        checkout.with['sparse-checkout'].trim().split('\n'),
        ['.github/workflows', 'governance']);
    assert.equal(checkout.with['persist-credentials'], false);
    assert.equal(job['runs-on'], 'ubuntu-24.04');
  }
});

test('the evaluation job runs the script of the master branch with the app token', async () => {
  const evaluator = loadYAML(path.join(__dirname, 'maintainer_approval.yml'));
  const job = evaluator.jobs.evaluate;
  const [checkout, token, script] = job.steps;
  assert.equal(job.steps.length, 3);
  // No other job can use the environment.
  assert.deepEqual(Object.keys(evaluator.jobs), ['evaluate']);
  // The actions that receive the private key and the token, at a commit.
  const pinned = (name) => new RegExp(`^actions/${name}@[0-9a-f]{40}$`);
  assert.match(checkout.uses, pinned('checkout'));
  assert.match(token.uses, pinned('create-github-app-token'));
  assert.match(script.uses, pinned('github-script'));
  // The checkout has no other input, for example another repository.
  assert.deepEqual(
      Object.keys(checkout.with).toSorted(),
      ['persist-credentials', 'ref', 'sparse-checkout']);
  // No step has other values of the workflow, for example the private key.
  assert.equal(evaluator.env, undefined);
  assert.equal(job.env, undefined);
  assert.equal(checkout.env, undefined);
  assert.equal(token.env, undefined);
  assert.equal(
      job.if,
      'github.repository == \'gvisor/gvisor\' && ' +
          'vars.MAINTAINER_APPROVAL_CLIENT_ID != \'\'');
  assert.deepEqual(job.environment, {name: 'maintainer-approval', deployment: false});
  assert.deepEqual(
      evaluator.concurrency,
      {group: 'maintainer-approval', 'cancel-in-progress': false});
  assert.deepEqual(evaluator.permissions, {contents: 'read'});
  assert.equal(job.permissions, undefined);
  assert.equal(checkout.with.ref, 'refs/heads/master');
  assert.equal(token.id, 'app-token');
  assert.deepEqual(token.with, {
    'client-id': '${{ vars.MAINTAINER_APPROVAL_CLIENT_ID }}',
    'private-key': '${{ secrets.MAINTAINER_APPROVAL_PRIVATE_KEY }}',
    'permission-contents': 'read',
    'permission-pull-requests': 'read',
    'permission-statuses': 'write',
  });
  assert.deepEqual(script.env, {
    APP_SLUG: '${{ steps.app-token.outputs.app-slug }}',
    APP_ID: 5829279,
  });
  assert.equal(
      script.with['github-token'], '${{ steps.app-token.outputs.token }}');
  // The job and its steps have no other setting, for example a condition
  // that skips the script, a setting that hides its failure, or an input
  // that sends the token to another server. The client sends a failed
  // request again.
  assert.deepEqual(
      Object.keys(job).toSorted(),
      ['environment', 'if', 'runs-on', 'steps', 'timeout-minutes']);
  assert.deepEqual(Object.keys(checkout).toSorted(), ['name', 'uses', 'with']);
  assert.deepEqual(Object.keys(token).toSorted(), ['id', 'name', 'uses', 'with']);
  assert.deepEqual(Object.keys(script).toSorted(), ['env', 'name', 'uses', 'with']);
  assert.deepEqual(
      Object.keys(script.with).toSorted(), ['github-token', 'retries', 'script']);
  assert.equal(script.with.retries, 3);

  // Run the inline script with fakes of the objects of actions/github-script.
  const AsyncFunction = (async () => {}).constructor;
  const calls = [];
  const fakeRequire = (name) => {
    assert.equal(
        path.resolve(REPO_ROOT, name), path.join(__dirname, 'maintainer_approval.js'));
    return async (args) => {
      // The inline script must wait for the result.
      await new Promise(setImmediate);
      calls.push(args);
    };
  };
  const [github, context, core] = [{}, {}, {}];
  const run = new AsyncFunction(
      'require', 'github', 'context', 'core', 'process', script.with.script);
  await run(fakeRequire, github, context, core, {env: {APP_SLUG: 'slug', APP_ID: '77'}});
  assert.deepEqual(calls, [{github, context, core, appSlug: 'slug', appID: 77}]);
  assert.equal(calls[0].github, github);
  assert.equal(calls[0].context, context);
  assert.equal(calls[0].core, core);
  // The inline script does not hide a failure of the script.
  const failing = () => async () => {
    throw new Error('the script failed');
  };
  await assert.rejects(
      run(failing, github, context, core, {env: {APP_SLUG: 'slug', APP_ID: '77'}}),
      /the script failed/);
});

test('compares the rosters with the accounts', async () => {
  const entry = (github, id, status) => ({github, github_id: id, status});
  const rosters = {
    'governance/maintainers.yaml': {
      maintainers: [
        entry('Alice', 1, 'ACTIVE'),
        entry('bob', 2, 'HIATUS_SINCE:2026-01-01'),
        // The username is of another account.
        entry('carol', 3, 'ACTIVE'),
        // A bot is not a maintainer.
        entry('robot[bot]', 4, 'ACTIVE'),
        // An emeritus maintainer is not examined.
        entry('erin', 5, 'EMERITUS_SINCE:2026-01-01'),
        // An entry without a username.
        {github_id: 6, status: 'ACTIVE'},
      ],
    },
    'governance/bots.yaml': {
      bots: [
        entry('helper[bot]', 7),
        // A user is not a bot.
        entry('dave', 8),
        // The account has no username.
        entry('ghost[bot]', 9),
      ],
    },
  };
  const accounts = {
    1: {login: 'alice', type: 'User'},
    2: {login: 'bob', type: 'User'},
    3: {login: 'mallory', type: 'User'},
    4: {login: 'robot[bot]', type: 'Bot'},
    6: {login: 'frank', type: 'User'},
    7: {login: 'helper[bot]', type: 'Bot'},
    8: {login: 'dave', type: 'User'},
    9: {type: 'Bot'},
  };
  const requests = [];
  const github = {
    request: async (route, params) => {
      assert.equal(route, 'GET /user/{account_id}');
      requests.push(params.account_id);
      return {data: accounts[params.account_id]};
    },
  };
  const load = (file) => {
    const name = Object.keys(rosters).find((n) => file.endsWith(n));
    assert.ok(name, file);
    return rosters[name];
  };
  assert.deepEqual(await maintainerApproval.rosterDifferences(github, load), [
    'carol (3) must be a User: the account with this ID is mallory, a User',
    'robot[bot] (4) must be a User: the account with this ID is robot[bot], a Bot',
    'undefined (6) must be a User: the account with this ID is frank, a User',
    'dave (8) must be a Bot: the account with this ID is dave, a User',
    'ghost[bot] (9) must be a Bot: the account with this ID is undefined, a Bot',
  ]);
  assert.deepEqual(requests, [1, 2, 3, 4, 6, 7, 8, 9]);
  // A failure to read an account, or an entry that is not valid, is an error.
  await assert.rejects(
      maintainerApproval.rosterDifferences(
          {request: async () => { throw new Error('no account'); }}, load),
      /no account/);
  rosters['governance/bots.yaml'].bots.push(entry('x', 0));
  await assert.rejects(
      maintainerApproval.rosterDifferences(github, load), /invalid github_id/);
});

test('the dry run sets no status', async () => {
  const tests = loadYAML(path.join(__dirname, 'maintainer_approval_test.yml'));
  const job = tests.jobs['dry-run'];
  assert.deepEqual(
      job.permissions,
      {contents: 'read', 'pull-requests': 'read', statuses: 'read'});
  const script = job.steps.at(-1);
  assert.equal(script.with['github-token'], undefined);
  assert.deepEqual(Object.keys(script.with).toSorted(), ['retries', 'script']);
  assert.equal(script.with.retries, 3);
  // The job and its steps have no other setting, for example a condition
  // that skips the dry run, or a setting that hides its failure.
  assert.deepEqual(
      Object.keys(job).toSorted(),
      ['if', 'permissions', 'runs-on', 'steps', 'timeout-minutes']);
  assert.equal(job.steps.length, 2);
  assert.deepEqual(Object.keys(job.steps[0]).toSorted(), ['uses', 'with']);
  assert.deepEqual(Object.keys(script).toSorted(), ['uses', 'with']);
  assert.match(script.uses, /^actions\/github-script@[0-9a-f]{40}$/);

  // Run the inline script. The real client must receive no status write.
  const AsyncFunction = (async () => {}).constructor;
  const requests = [];
  const real = {
    graphql: () => {},
    request: async (route, parameters) => {
      requests.push([route, parameters]);
      return {data: [{type: 'deletion'}]};
    },
    rest: {
      repos: {
        createCommitStatus: () => {
          throw new Error('a status write');
        },
      },
    },
  };
  const failed = [];
  const core = {setFailed: (message) => failed.push(message)};
  const context = {};
  let commits = 0;
  let failure;
  const fakeRequire = (name) => async (args) => {
    assert.equal(
        path.resolve(REPO_ROOT, name), path.join(__dirname, 'maintainer_approval.js'));
    // The inline script must wait for the result.
    await new Promise(setImmediate);
    if (failure) {
      throw failure;
    }
    // The failures of the script go to the real core.
    assert.equal(args.core, core);
    assert.equal(args.context, context);
    assert.equal(args.github.graphql, real.graphql);
    assert.deepEqual(Object.keys(args.github).sort(), ['graphql', 'request', 'rest']);
    // The run has the name of an app, and it does not wait after a write that
    // it does not make.
    assert.equal(typeof args.appSlug, 'string');
    assert.notEqual(args.appSlug, '');
    assert.ok(Number.isSafeInteger(args.appID) && args.appID > 0);
    assert.equal(await args.sleep(3600000), undefined);
    // The requests go to the real client. The rules of a branch are read, and
    // then they are as the script needs them.
    requests.length = 0;
    const activity = 'GET /repos/{owner}/{repo}/activity';
    const rules = 'GET /repos/{owner}/{repo}/rules/branches/{branch}';
    assert.deepEqual(
        await args.github.request(activity, {ref: 'x'}), {data: [{type: 'deletion'}]});
    // The rules require two approvals: the script reports rules that require
    // one approval and no status.
    assert.deepEqual(await args.github.request(rules, {branch: 'master'}), {
      data: [{
        type: 'pull_request',
        parameters: {...RULE_PARAMETERS, required_approving_review_count: 2},
      }],
    });
    assert.deepEqual(
        requests, [[activity, {ref: 'x'}], [rules, {branch: 'master'}]]);
    // A status write does not go to the real client.
    assert.deepEqual(await args.github.rest.repos.createCommitStatus({}), {data: {}});
    return {commits, written: 0};
  };
  const run = new AsyncFunction(
      'require', 'github', 'context', 'core', script.with.script);
  await run(fakeRequire, real, context, core);
  assert.deepEqual(failed, ['the script examined no pull request']);
  commits = 2;
  failed.length = 0;
  await run(fakeRequire, real, context, core);
  assert.deepEqual(failed, []);
  // The inline script does not hide a failure of the script.
  failure = new Error('the script failed');
  await assert.rejects(run(fakeRequire, real, context, core), /the script failed/);
});
