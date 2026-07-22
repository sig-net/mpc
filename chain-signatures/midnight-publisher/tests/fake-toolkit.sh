#!/usr/bin/env bash
# Test stub: records each invocation's argv to $FAKE_TOOLKIT_LOG and succeeds.
echo "$*" >> "${FAKE_TOOLKIT_LOG:?}"
exit 0
