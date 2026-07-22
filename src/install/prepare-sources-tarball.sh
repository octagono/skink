#!/bin/bash
tmp=$(mktemp -d)
echo $VERSION
git clone -b v${VERSION} --depth 1 https://github.com/octagono/skink $tmp/Skink-${VERSION}
(cd $tmp/Skink-${VERSION} && go mod tidy && go mod vendor)
(cd $tmp && tar -cvzf Skink_${VERSION}_src.tar.gz Skink-${VERSION})
mv $tmp/Skink_${VERSION}_src.tar.gz dist/
