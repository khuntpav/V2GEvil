#!/usr/bin/env zsh
# Change it to #!/usr/bin/env bash
# If you use bash

cp .env.evcc .env

make install-local
make poetry-shell
