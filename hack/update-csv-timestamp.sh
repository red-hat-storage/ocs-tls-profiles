#!/bin/bash

# Only process bundle if it's tracked by git
if git ls-files --error-unmatch ./bundle >/dev/null 2>&1; then
    if git diff --quiet -I'^( )+createdAt: ' ./bundle; then
        git checkout --quiet ./bundle
    fi
fi
