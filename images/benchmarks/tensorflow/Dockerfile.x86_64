FROM tensorflow/tensorflow:1.13.2

RUN apt-get update \
    && apt-get install -y git
RUN git clone --depth 1 https://github.com/aymericdamien/TensorFlow-Examples.git
RUN python -m pip install -U pip setuptools
RUN python -m pip install matplotlib
