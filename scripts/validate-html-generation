#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${DIR}/.validate"

IFS=$'\n'
files=( $(validate_diff --diff-filter=ACMR --name-only -- 'static/index.html' || true) )
unset IFS

if [ ${#files[@]} -gt 0 ]; then
	# We run go generate to and see if we have a diff afterwards
	go generate >/dev/null
	# Let see if the working directory is clean
	diffs="$(git status --porcelain -- static.go 2>/dev/null)"
	if [ "$diffs" ]; then
		{
			echo 'The result of go generate differs'
			echo
			echo "$diffs"
			echo
			echo 'Please re-run go generate'
			echo
		} >&2
		false
	else
		echo 'Congratulations! File generation is done correctly.'
	fi
fi
