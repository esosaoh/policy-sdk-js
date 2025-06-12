setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    POLICY_WASM="dist/policy.wasm"
    ANNOTATED_WASM="annotated-policy.wasm"
    METADATA_YML="metadata.yml"

    npm install --save-dev esbuild webpack ts-loader
    npm run build

    mkdir -p dist
    [ -f dist/bundle.js ] || { echo "dist/bundle.js not found after npm run build" >&2; return 1; }
    PLUGIN_PATH="../javy-plugin-kubewarden/javy-plugin-kubewarden.wasm"
    [ -f "$PLUGIN_PATH" ] || { echo "Plugin not found at $PLUGIN_PATH" >&2; return 1; }

    javy build dist/bundle.js -C plugin="$PLUGIN_PATH" -o "$POLICY_WASM"

    cat <<EOF > "$METADATA_YML"
title: Test Policy
description: Test policy for OCI manifest digest
source: https://github.com/kubewarden/policy-sdk-js
license: Apache-2.0
execution_mode: kubewarden-wasi
mutating: false
rules: []
EOF
    # Annotate policy
    kwctl annotate -m "$METADATA_YML" -o "$ANNOTATED_WASM" "$POLICY_WASM"
    # Create replay-session.yml
    cat <<EOF > replay-session.yml
---
- type: Exchange
  request: |
    !OciManifestDigest
    image: docker.io/library/busybox:1.36
  response:
    type: Success
    payload: '{"digest":"sha256:7edf5efe6b86dbf01ccc3c76b32a37a8e23b84e6bad81ce8ae8c221fa456fda8"}'
- type: Exchange
  request: |
    !DNSLookupHost
    host: google.com
  response:
    type: Success
    payload: '{"ips":["2607:f8b0:4020:801::200e","142.250.142.142"]}'
EOF
}

@test "should return valid digest for busybox:1.36" {
    run kwctl run --allow-context-aware --replay-host-capabilities-interactions replay-session.yml "$ANNOTATED_WASM" -r ./test_data/no_privileged.json
    echo "Status: $status"
    echo "Output: $output"
    assert_success
    assert_output --partial '"allowed": true'
    assert_output --partial '"digest":"sha256:7edf5efe6b86dbf01ccc3c76b32a37a8e23b84e6bad81ce8ae8c221fa456fda8"'
}

teardown() {
    rm -f "$POLICY_WASM" "$ANNOTATED_WASM"
}