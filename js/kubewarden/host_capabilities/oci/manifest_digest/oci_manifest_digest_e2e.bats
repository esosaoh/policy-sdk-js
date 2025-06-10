setup() {
    load '../../../../test_helper/bats-support/load'
    load '../../../../test_helper/bats-assert/load'
    POLICY_WASM="test-policy.wasm"
    ANNOTATED_WASM="annotated-test-policy.wasm"
    npm install --save-dev esbuild
    npm run build
    javy build test-policy/src/index.js -C plugin=../../../../../javy-plugin-kubewarden/javy-plugin-kubewarden.wasm -o "$POLICY_WASM"
    cat <<EOF > test-policy/metadata.yml
title: Test Policy
description: Test policy for OCI manifest digest
source: https://github.com/kubewarden/policy-sdk-js
license: Apache-2.0
execution_mode: kubewarden-wapc
mutating: false
rules: []
EOF
    kwctl annotate -m test-policy/metadata.yml -o "$ANNOTATED_WASM" "$POLICY_WASM"
    cat <<EOF > test-policy/replay-session.yml
---
- type: Exchange
  request: |
    !OCIGetManifestDigest
    image: docker.io/library/busybox:1.36
  response:
    type: Success
    payload: '{"digest":"sha256:7edf5efe6b86dbf01ccc3c76b32a37a8e23b84e6bad81ce8ae8c221fa456fda8"}'
EOF
}

@test "should return valid digest for busybox:1.36" {
    run --separate-stderr kwctl run --allow-context-aware --replay-host-capabilities-interactions test-policy/replay-session.yml --request-path - "$ANNOTATED_WASM" < <(echo '{"request":"data"}')
    echo "Exit status: $status" >&3
    echo "Output: $output" >&3
    echo "Stderr: $stderr" >&3
    assert_success
    assert_output --partial 'Digest for busybox:1.36: sha256:7edf5efe6b86dbf01ccc3c76b32a37a8e23b84e6bad81ce8ae8c221fa456fda8'
}

teardown() {
    rm -f test-policy.js "$POLICY_WASM" "$ANNOTATED_WASM" test-policy/metadata.yml test-policy/replay-session.yml
}