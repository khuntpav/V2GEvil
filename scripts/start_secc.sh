#!/usr/bin/env zsh

cp .env.secc .env

make install-local
# $ poetry shell
# $ python iso15118/secc/start_secc.py
# make poetry-shell
# make run-secc
poetry run make run-secc
