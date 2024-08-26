#!/usr/bin/env zsh

cp .env.secc .env

make install-local
make poetry-shell
