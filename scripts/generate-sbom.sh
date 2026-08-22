#!/bin/sh
set -eu

temporary=$(mktemp "${TMPDIR:-/tmp}/isecure-rust-client-sbom.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

cargo metadata --locked --format-version 1 |
    jq '{
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        metadata: {
            component: {
                type: "library",
                name: "isecure-rust-client",
                version: (.packages[] | select(.name == "isecure-rust-client") | .version),
                purl: ("pkg:cargo/isecure-rust-client@" + (.packages[] | select(.name == "isecure-rust-client") | .version))
            }
        },
        components: ([
            .packages[] |
            select(.source != null) |
            {
                type: "library",
                name,
                version,
                purl: ("pkg:cargo/" + .name + "@" + .version),
                licenses: [{ expression: (.license | gsub("MIT/Apache-2.0"; "MIT OR Apache-2.0")) }]
            }
        ] | sort_by(.name, .version))
    }' >"$temporary"

mv "$temporary" sbom.cdx.json
trap - EXIT HUP INT TERM
