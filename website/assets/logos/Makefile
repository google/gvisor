#!/usr/bin/make -f

srcs := $(wildcard *.svg)
dsts := $(patsubst %.svg,%.png,$(srcs))

all: $(dsts)
.PHONY: all

%.png %-16.png %-128.png %-1024.png: %.svg
	@inkscape -z -e $*.png $<
	@inkscape -z -w 16 -e $*-16.png $<
	@inkscape -z -w 128 -e $*-128.png $<
	@inkscape -z -w 1024 -e $*-1024.png $<
