#!/bin/bash -e

cd "$(dirname $0)"

if [ ! -f "tlsproxy/Dockerfile" ]; then
  git clone https://github.com/c2fmzq/tlsproxy.git
fi
touch tlsproxy/version.sh
docker build -t c2fmzq/tlsproxy:integrationtest ./tlsproxy

if [ ! -f "photos/Dockerfile" ]; then
  git clone https://github.com/c2fmzq/photos.git
fi
docker build -t c2fmzq/c2fmzq-server:integrationtest ./photos

if [ ! -f "sshterm/build.sh" ]; then
  git clone https://github.com/c2fmzq/sshterm.git
fi
chmod +w sshterm/docroot
cp $(go env GOROOT)/lib/wasm/wasm_exec.js ./sshterm/docroot/
./sshterm/build.sh

export CGO_ENABLED=0
(cd ./mock-oidc-server && go build -o mock-oidc-server .)
(cd ./mock-ssh-server && go build -o mock-ssh-server .)
(cd ./tests && go build -o integration-tests .)

docker build -t c2fmzq/mock-oidc-server:integrationtest ./mock-oidc-server
docker build -t c2fmzq/mock-ssh-server:integrationtest ./mock-ssh-server
docker build -t c2fmzq/integration-tests:integrationtest ./tests

docker compose -f ./docker-compose.yaml up \
  --abort-on-container-exit \
  --exit-code-from=tests
RES=$?
docker compose -f ./docker-compose.yaml rm -f

if [[ $RES == 0 ]]; then
  echo PASS
else
  echo FAIL
  exit 1
fi
