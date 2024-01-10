#!/usr/bin/env zsh

cp .env.evcc .env

make install-local
poetry run make run-evcc
