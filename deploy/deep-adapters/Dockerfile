# Linux/amd64 worker image recipes. Digests below were resolved from the
# upstream registries; update only with a reviewed version and digest pair.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS python-source
FROM debian:forky-slim@sha256:3c80e257eff6274d593eb33a94bda5174ccd619836e6a728a73e11c97f2213e3 AS sdk
USER 0:0
# The signed immutable archive supplies fixes absent from Bookworm/Trixie.
# Valid-Until is disabled only for this historical snapshot; signature and
# package hash verification remain enforced by apt.
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/20261008T000000Z/\nSuites: forky sid\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' > /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get -t forky install -y --no-install-recommends ca-certificates libbz2-1.0 libcrypt1 libdb5.3t64 libffi8 libgdbm6t64 liblzma5 libncursesw6 libreadline8t64 libsqlite3-0 libssl3t64=3.6.5-1 openssl=3.6.5-1 openssl-provider-legacy=3.6.5-1 libuuid1 zlib1g libzstd1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=python-source /usr/local/ /usr/local/
COPY deploy/deep-adapters/requirements-bootstrap.txt /tmp/requirements-bootstrap.txt
RUN ldconfig && python -m pip uninstall -y setuptools wheel \
    && python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-bootstrap.txt \
    && python -c 'import ssl,sqlite3,ctypes,bz2,lzma,readline,curses,uuid; print(ssl.OPENSSL_VERSION,sqlite3.sqlite_version)'
COPY factoryline/__init__.py factoryline/deep_audit_io.py factoryline/deep_audit_sarif.py factoryline/runtime_audit_common.py factoryline/runtime_audit_process.py /usr/local/lib/python3.11/site-packages/factoryline/
COPY --chmod=0555 deploy/deep-adapters/entrypoint /opt/factory/bin/audit-adapter
RUN mkdir -p /src /out /opt/factory/rules
LABEL io.code-factory.protocol="factory.deep-worker.v1"
USER 1000:1000
WORKDIR /src
ENTRYPOINT ["/opt/factory/bin/audit-adapter"]

FROM semgrep/semgrep:1.141.0@sha256:64102d27111415eb3d51a313bf69739030a069716d7ba4827c2f8842c02b481e AS semgrep-tool
FROM semgrep-tool AS semgrep-worker
USER 0:0
COPY factoryline/__init__.py factoryline/deep_audit_io.py factoryline/runtime_audit_common.py factoryline/runtime_audit_process.py /usr/lib/python3.12/site-packages/factoryline/
COPY --chmod=0555 deploy/deep-adapters/entrypoint /opt/factory/bin/audit-adapter
COPY --chown=1000:1000 deploy/deep-adapters/profiles/semgrep-pattern-limited.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/semgrep-pattern-limited.yml /opt/factory/rules/semgrep-pattern-limited.yml
RUN mkdir -p /src /out /opt/factory/rules
WORKDIR /src
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="pattern-limited"

ENTRYPOINT ["/usr/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS codeql-python-worker
USER 0:0
ADD --checksum=sha256:1ec99cfa9420f04c2330784b4ddb8363a0dd67c3e4471cd93963c50e6c433717 https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-linux64.tar.zst /tmp/codeql-bundle.tar.zst
COPY deploy/deep-adapters/requirements-codeql.txt /tmp/requirements-codeql.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-codeql.txt
RUN python -c 'import tarfile,zstandard; stream=zstandard.ZstdDecompressor().stream_reader(open("/tmp/codeql-bundle.tar.zst","rb")); tarfile.open(fileobj=stream,mode="r|").extractall("/opt/codeql",filter="data")' && rm -f /tmp/codeql-bundle.tar.zst
RUN /opt/codeql/codeql/codeql query compile --precompile --threads=4 --ram=4096 -- /opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11/codeql-suites/python-security-extended.qls && find /opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11 -type f -name '*.qlx' -exec chmod 0444 {} +
COPY --chown=1000:1000 deploy/deep-adapters/profiles/codeql-python-full.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="interprocedural-full" io.code-factory.language="python"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM codeql-python-worker AS codeql-javascript-worker
USER 0:0
RUN chmod -R a+rX /opt/codeql/codeql/qlpacks/codeql/javascript-queries/2.4.6
RUN /opt/codeql/codeql/codeql resolve queries --format=json /opt/codeql/codeql/qlpacks/codeql/javascript-queries/2.4.6/codeql-suites/javascript-security-extended.qls > /tmp/native-queries.json && python -c 'import json,pathlib; q=json.load(open("/tmp/native-queries.json")); assert q and all(pathlib.Path(p).with_suffix(".qlx").is_file() for p in q); print("Verified bundled compiled queries:",len(q))' && rm /tmp/native-queries.json
COPY --chown=1000:1000 deploy/deep-adapters/profiles/codeql-javascript-full.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="interprocedural-full" io.code-factory.language="javascript-typescript"

FROM codeql-python-worker AS codeql-actions-worker
USER 0:0
RUN chmod -R a+rX /opt/codeql/codeql/qlpacks/codeql/actions-queries/0.6.36
RUN /opt/codeql/codeql/codeql resolve queries --format=json /opt/codeql/codeql/qlpacks/codeql/actions-queries/0.6.36/codeql-suites/actions-security-extended.qls > /tmp/native-queries.json && python -c 'import json,pathlib; q=json.load(open("/tmp/native-queries.json")); assert q and all(pathlib.Path(p).with_suffix(".qlx").is_file() for p in q); print("Verified bundled compiled queries:",len(q))' && rm /tmp/native-queries.json
COPY --chown=1000:1000 deploy/deep-adapters/profiles/codeql-actions-full.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="interprocedural-full" io.code-factory.language="actions"

FROM ghcr.io/google/osv-scanner:v2.2.0@sha256:a6e641ed444704349d4319b80019654643aa9036b76ee1699a9f927dfe1b0d5c AS osv-tool
FROM anchore/syft:v1.33.0@sha256:cefadcf11bd9cce9e3ec5248bb1538a84e33d519486c1b4523ac155c9b5f5033 AS syft-tool
FROM sdk AS osv-worker
COPY --from=osv-tool /osv-scanner /usr/local/bin/osv-scanner
COPY --chmod=0555 deploy/deep-adapters/bin/osv-offline /opt/factory/bin/osv-offline
COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt /opt/factory/rules/osv-scanner.toml
ADD --checksum=sha256:36ef7d92e174230b8c7c26b952562be23837472c2239b6752de64d5d683a800e https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip?generation=1791370055357324 /tmp/osv-pypi-all.zip
USER 0:0
RUN mkdir -p /opt/factory/osv-db/osv-scanner/PyPI && mv /tmp/osv-pypi-all.zip /opt/factory/osv-db/osv-scanner/PyPI/all.zip && chmod 0444 /opt/factory/osv-db/osv-scanner/PyPI/all.zip
COPY --chown=1000:1000 deploy/deep-adapters/profiles/osv.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.family="dependencies" io.code-factory.mode="offline-pypi-snapshot"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS syft-worker
COPY --from=syft-tool /syft /usr/local/bin/syft
COPY --chown=1000:1000 deploy/deep-adapters/profiles/syft.json /opt/factory/adapter-profile.json
LABEL io.code-factory.configured="true" io.code-factory.family="dependencies" io.code-factory.mode="sbom-only"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM golang@sha256:0b4f8c5d414756a53ba0e4d235151f9b246552e512c3feaad5f9a3251376b279 AS gitleaks-build
ADD --checksum=sha256:ab481824ccba4e14fd61e290014d961f06c4d4a7597783ec7d22f8a1ef241322 https://github.com/zricethezav/gitleaks/archive/4fb43823ef3d152d239e92d7d5cb04783b548062.tar.gz /tmp/gitleaks.tar.gz
RUN mkdir -p /src && tar -xzf /tmp/gitleaks.tar.gz --strip-components=1 -C /src && rm /tmp/gitleaks.tar.gz
COPY deploy/deep-adapters/gitleaks-rule-ledger.patch /tmp/gitleaks-rule-ledger.patch
WORKDIR /src
RUN git -C /src init -q \
    && git -C /src apply --check /tmp/gitleaks-rule-ledger.patch \
    && git -C /src apply /tmp/gitleaks-rule-ledger.patch \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -X github.com/zricethezav/gitleaks/v8/cmd.Version=8.28.0" -o /gitleaks .
FROM sdk AS gitleaks-worker
COPY --from=gitleaks-build /gitleaks /usr/bin/gitleaks
COPY --chown=1000:1000 deploy/deep-adapters/profiles/gitleaks.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/gitleaks-8.28.0.toml /opt/factory/rules/gitleaks.toml
COPY --chown=1000:1000 deploy/deep-adapters/rules/GITLEAKS-LICENSE.txt /opt/factory/rules/GITLEAKS-LICENSE.txt
COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt /opt/factory/rules/empty-gitleaksignore
LABEL io.code-factory.configured="true" io.code-factory.gitleaks-source="4fb43823ef3d152d239e92d7d5cb04783b548062" io.code-factory.gitleaks-ledger="gitleaks.factory-rule-ledger.v1"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM aquasec/trivy:0.68.1@sha256:52e6fb1ff6a8232d6ec480ca9dd0b8db6728e252d092cb7712df7103ba09502e AS trivy-tool
FROM sdk AS trivy-worker
COPY --from=trivy-tool /usr/local/bin/trivy /usr/local/bin/trivy
COPY --chown=1000:1000 deploy/deep-adapters/profiles/trivy-config.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt /opt/factory/rules/empty-trivyignore
COPY --chown=1000:1000 deploy/deep-adapters/rules/trivy.yaml /opt/factory/rules/trivy.yaml
LABEL io.code-factory.configured="true"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS runtime-worker
USER 0:0
COPY deploy/deep-adapters/requirements-runtime.txt /tmp/requirements-runtime.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-runtime.txt
USER 1000:1000
COPY --chown=1000:1000 deploy/deep-adapters/profiles/runtime-coverage.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/runtime-control.toml /opt/factory/rules/runtime-control.toml
LABEL io.code-factory.configured="true" io.code-factory.harness="candidate-supplied"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS fuzz-worker
USER 0:0
COPY deploy/deep-adapters/requirements-fuzz.txt /tmp/requirements-fuzz.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-fuzz.txt
USER 1000:1000
COPY --chown=1000:1000 deploy/deep-adapters/profiles/atheris.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/fuzz-control.json /opt/factory/rules/fuzz-control.json
LABEL io.code-factory.configured="true" io.code-factory.harness="candidate-supplied"
ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]

# Exact stable distribution plus a source-bound native invocation ledger.
FROM ghcr.io/zaproxy/zaproxy@sha256:17711b689795c5519c512bafee363b3976ce8457358db8405c6961e18c72dc66 AS zap-native-build
USER 0:0
ADD --checksum=sha256:774a41e0f7089332656a8b222fc07e96fe29b390a6432719b77595775731b228 https://raw.githubusercontent.com/zaproxy/zaproxy/8a1bff313f4d183dba5aa154ecbe89ad751c9153/zap/src/main/java/org/parosproxy/paros/core/scanner/HostProcess.java /tmp/zap-source/zap/src/main/java/org/parosproxy/paros/core/scanner/HostProcess.java
ADD --checksum=sha256:25ecec9175591616f0c38e7209476723aedc4bbae716308038a5687cf69c29e4 https://raw.githubusercontent.com/zaproxy/zaproxy/8a1bff313f4d183dba5aa154ecbe89ad751c9153/zap/src/main/java/org/parosproxy/paros/core/scanner/AbstractPlugin.java /tmp/zap-source/zap/src/main/java/org/parosproxy/paros/core/scanner/AbstractPlugin.java
COPY deploy/deep-adapters/zap-rule-ledger.patch /tmp/zap-rule-ledger.patch
WORKDIR /tmp/zap-source
RUN echo '91b0fbd609dc1ac88319ec5b718c586e0f33014b24221e9d055673c49695b74f  /tmp/zap-rule-ledger.patch' | sha256sum -c - \
    && git apply --check /tmp/zap-rule-ledger.patch \
    && git apply /tmp/zap-rule-ledger.patch \
    && mkdir -p /tmp/zap-classes \
    && javac --release 17 -proc:none -cp '/zap/zap-2.17.0.jar:/zap/lib/*:/zap/plugin/*' -d /tmp/zap-classes zap/src/main/java/org/parosproxy/paros/core/scanner/HostProcess.java zap/src/main/java/org/parosproxy/paros/core/scanner/AbstractPlugin.java \
    && jar --update --file /zap/zap-2.17.0.jar -C /tmp/zap-classes .
FROM sdk AS zap-worker
USER 0:0
RUN apt-get update \
    && apt-get -t forky install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=zap-native-build /zap /zap
COPY --from=zap-native-build /usr/lib/jvm/java-17-openjdk-amd64 /opt/factory/java
COPY --from=zap-native-build /etc/java-17-openjdk /etc/java-17-openjdk
ENV JAVA_HOME=/opt/factory/java
ENV PATH=/opt/factory/java/bin:$PATH
RUN mkdir -p /home/factory /out && chown -R 1000:1000 /home/factory /out
ENV HOME=/home/factory
USER 1000:1000
WORKDIR /src
LABEL io.code-factory.configured="false" io.code-factory.zap-source="8a1bff313f4d183dba5aa154ecbe89ad751c9153" io.code-factory.zap-ledger="factory.zap-rule-ledger.v1"
ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
