FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            fio \
        && rm -rf /var/lib/apt/lists/*

# Parameterized test.
ENV test write
ENV ioengine sync
ENV size 5000000
ENV iodepth 4
ENV blocksize "1m"
ENV time ""
ENV path "/disk/file.dat"
ENV ramp_time 0

CMD ["sh", "-c", "fio --output-format=json --name=test --ramp_time=${ramp_time} --ioengine=${ioengine} --size=${size} \
--filename=${path} --iodepth=${iodepth} --bs=${blocksize} --rw=${test} ${time}"]



