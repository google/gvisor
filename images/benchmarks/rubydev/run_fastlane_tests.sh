#!/bin/bash
# Copyright 2022 The gVisor Authors.
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

set -euo pipefail

# Run only a subset of tests, otherwise this is simply too long of a benchmark.
# This list was compiled using:
#   $ find -name '*_spec.rb' | shuf | head -100 | cut -d/ -f2- | sort
specs=(
  cert/spec/commands_generator_spec.rb
  credentials_manager/spec/account_manager_spec.rb
  fastlane/spec/action_metadata_spec.rb
  fastlane/spec/actions_helper_spec.rb
  fastlane/spec/actions_specs/appetize_view_url_generator_spec.rb
  fastlane/spec/actions_specs/apteligent_spec.rb
  fastlane/spec/actions_specs/backup_file_spec.rb
  fastlane/spec/actions_specs/clean_cocoapods_cache_spec.rb
  fastlane/spec/actions_specs/delete_keychain_spec.rb
  fastlane/spec/actions_specs/deploygate_spec.rb
  fastlane/spec/actions_specs/ensure_git_status_clean_spec.rb
  fastlane/spec/actions_specs/ensure_xcode_version_spec.rb
  fastlane/spec/actions_specs/get_github_release_spec.rb
  fastlane/spec/actions_specs/git_branch_spec.rb
  fastlane/spec/actions_specs/git_pull_spec.rb
  fastlane/spec/actions_specs/hg_add_tag_spec.rb
  fastlane/spec/actions_specs/hg_commit_version_bump_spec.rb
  fastlane/spec/actions_specs/hockey_spec.rb
  fastlane/spec/actions_specs/import_certificate_spec.rb
  fastlane/spec/actions_specs/import_spec.rb
  fastlane/spec/actions_specs/jazzy_spec.rb
  fastlane/spec/actions_specs/push_git_tags_spec.rb
  fastlane/spec/actions_specs/puts_spec.rb
  fastlane/spec/actions_specs/reset_git_repo_spec.rb
  fastlane/spec/actions_specs/rsync_spec.rb
  fastlane/spec/actions_specs/say_spec.rb
  fastlane/spec/actions_specs/set_changelog_spec.rb
  fastlane/spec/actions_specs/set_info_plist_value_spec.rb
  fastlane/spec/actions_specs/set_pod_key_spec.rb
  fastlane/spec/actions_specs/setup_ci_spec.rb
  fastlane/spec/actions_specs/setup_circle_ci_spec.rb
  fastlane/spec/actions_specs/spm_spec.rb
  fastlane/spec/actions_specs/swiftlint_spec.rb
  fastlane/spec/actions_specs/testfairy_spec.rb
  fastlane/spec/actions_specs/update_app_identifier_spec.rb
  fastlane/spec/actions_specs/update_keychain_access_groups_spec.rb
  fastlane/spec/actions_specs/update_project_provisioning_spec.rb
  fastlane/spec/actions_specs/version_bump_podspec_spec.rb
  fastlane/spec/actions_specs/xcode_server_get_assets_spec.rb
  fastlane/spec/actions_specs/xcodebuild_spec.rb
  fastlane/spec/actions_specs/xctool_action_spec.rb
  fastlane/spec/actions_specs/zip_spec.rb
  fastlane/spec/command_line_handler_spec.rb
  fastlane/spec/env_spec.rb
  fastlane/spec/gradle_helper_spec.rb
  fastlane/spec/helper/adb_helper_spec.rb
  fastlane/spec/helper/s3_client_helper_spec.rb
  fastlane/spec/helper/xcodeproj_helper_spec.rb
  fastlane/spec/lane_list_spec.rb
  fastlane/spec/runner_spec.rb
  fastlane_core/spec/app_identifier_guesser_spec.rb
  fastlane_core/spec/configuration_file_spec.rb
  fastlane_core/spec/configuration_spec.rb
  fastlane_core/spec/core_ext/cfpropertylist_ext_spec.rb
  fastlane_core/spec/core_ext/shellwords_ext_spec.rb
  fastlane_core/spec/fastlane_user_dir_spec.rb
  fastlane_core/spec/ios_app_identifier_guesser_spec.rb
  fastlane_core/spec/languages_spec.rb
  gym/spec/code_signing_mapping_spec.rb
  gym/spec/gymfile_spec.rb
  gym/spec/options_spec.rb
  gym/spec/xcodebuild_fixes/generic_archive_fix_spec.rb
  match/spec/encryption/openssl_spec.rb
  match/spec/storage/gitlab/client_spec.rb
  precheck/spec/rules/curse_words_rule_spec.rb
  precheck/spec/rules/rule_spec.rb
  precheck/spec/rules/unreachable_urls_rule_spec.rb
  scan/spec/commands_generator_spec.rb
  scan/spec/error_handler_spec.rb
  scan/spec/test_result_parser_spec.rb
  screengrab/spec/commands_generator_spec.rb
  sigh/spec/manager_spec.rb
  sigh/spec/runner_spec.rb
  snapshot/spec/test_command_generator_xcode_8_spec.rb
  spaceship/spec/connect_api/client_spec.rb
  spaceship/spec/connect_api/models/app_spec.rb
  spaceship/spec/connect_api/models/app_store_version_spec.rb
  spaceship/spec/connect_api/models/beta_feedback_spec.rb
  spaceship/spec/connect_api/models/build_beta_detail_spec.rb
  spaceship/spec/connect_api/models/build_delivery_spec.rb
  spaceship/spec/connect_api/models/bundle_id_spec.rb
  spaceship/spec/connect_api/testflight/testflight_client_spec.rb
  spaceship/spec/connect_api/token_spec.rb
  spaceship/spec/du/du_client_spec.rb
  spaceship/spec/portal/app_group_spec.rb
  spaceship/spec/portal/app_spec.rb
  spaceship/spec/portal/enterprise_spec.rb
  spaceship/spec/portal/merchant_spec.rb
  spaceship/spec/portal/passbook_spec.rb
  spaceship/spec/spaceship_base_spec.rb
  spaceship/spec/spaceship_spec.rb
  spaceship/spec/test_flight/app_test_info_spec.rb
  spaceship/spec/tunes/app_analytics_spec.rb
  spaceship/spec/tunes/app_submission_spec.rb
  spaceship/spec/tunes/app_version_spec.rb
  spaceship/spec/tunes/application_spec.rb
  spaceship/spec/tunes/b2b_organization_spec.rb
  spaceship/spec/tunes/members_spec.rb
  spaceship/spec/two_step_or_factor_client_spec.rb
  supply/spec/commands_generator_spec.rb
)
pattern="{"
for spec in "${specs[@]}"; do
  pattern="${pattern}${spec},"
done
pattern="$(echo "$pattern" | sed -r 's/,$//')}"
exec bundle exec rspec --pattern "$pattern"
