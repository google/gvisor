#!/usr/bin/make -f

srcs := $(wildcard *.svg)
dsts := $(patsubst %.svg,%.png,$(srcs))

all: $(dsts)
.PHONY: all

%.png: %.svg
	@inkscape -z -e $@ $<
