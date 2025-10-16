#!/bin/bash -e

cd "$(dirname $0)"

if [[ ! -f "tlsproxy/Dockerfile" ]]; then
  git clone https://github.com/c2fmzq/tlsproxy.git
fi
if [[ -n "${TLSPROXY_BRANCH}" ]]; then
  (cd tlsproxy && git fetch && git switch --detach "${TLSPROXY_BRANCH}")
fi
touch tlsproxy/version.sh
docker build -t c2fmzq/tlsproxy:integrationtest ./tlsproxy

if [[ ! -f "photos/Dockerfile" ]]; then
  git clone https://github.com/c2fmzq/photos.git
fi
if [[ -n "${PHOTOS_BRANCH}" ]]; then
  (cd photos && git fetch && git switch --detach "${PHOTOS_BRANCH}")
fi
docker build -t c2fmzq/c2fmzq-server:integrationtest ./photos

if [[ ! -f "sshterm/build.sh" ]]; then
  git clone https://github.com/c2fmzq/sshterm.git
fi
if [[ -n "${SSHTERM_BRANCH}" ]]; then
  (cd sshterm && git fetch && git switch --detach "${SSHTERM_BRANCH}")
fi
./sshterm/build.sh
cp -f ./testdata/sshterm-config.json ./sshterm/docroot/config.json

export CGO_ENABLED=0
(cd ./mock-oidc-server && go build -o mock-oidc-server .)
(cd ./mock-ssh-server && go build -o mock-ssh-server .)
(cd ./devtests && go test -c -o integration-tests .)

docker build -t c2fmzq/mock-oidc-server:integrationtest ./mock-oidc-server
docker build -t c2fmzq/mock-ssh-server:integrationtest ./mock-ssh-server
docker build -t c2fmzq/integration-tests:integrationtest ./devtests

docker compose -f ./docker-compose.yaml up \
  --abort-on-container-exit \
  --exit-code-from=devtests
RES=$?
docker compose -f ./docker-compose.yaml rm -f

if [[ $RES == 0 ]]; then
  echo PASS
else
  echo FAIL
  exit 1
fi
