FROM ubuntu
RUN apt-get -q update && apt-get install -qqy git rsync
