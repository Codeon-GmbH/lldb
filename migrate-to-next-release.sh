#!/usr/bin/env bash

set -x

OLD_LLVM_BRANCH="release_40"
OLD_MULLE_DEV_BRANCH="mulle_lldb_40"
NEW_LLVM_BRANCH="release_50"
NEW_MULLE_DEV_BRANCH="mulle_lldb_50"

LLVM_REMOTE="llvm"

#
# be in mulle-lldb-4.0.0
# get new version from LLVM (github)
#
git remote add "${LLVM_REMOTE}" https://github.com/llvm-mirror/lldb.git 2> /dev/null
git fetch "${LLVM_REMOTE}"


# find the place we forked from last time
ancestor="`git merge-base "${LLVM_REMOTE}/${OLD_LLVM_BRANCH}" "${OLD_MULLE_DEV_BRANCH}"`"
[ -z "${anchestor}" ] && echo "No common ancestor found" &&

# create a new temporary branch to contain squashed patchset
echo "### 1: Checkout" >&2 &&

git checkout -b "tmp_${NEW_MULLE_DEV_BRANCH}" "${ancestor}" &&

#
# squash everything into new branch
# this helps weed out re-edits and commits that weren't useful
# easing the conflict resolution
#
# ???? git merge --squash "tmp_${OLD_MULLE_DEV_BRANCH}"
echo "### 2: Squash Merge" >&2 &&

git merge --squash "${OLD_MULLE_DEV_BRANCH}" &&

# commit stuff
echo "### 3: Commit" >&2 &&

git commit -m "${OLD_MULLE_DEV_BRANCH} squashed" &&

# remember until where did we squash the old branch (in case of
# future edits)
echo "### 4: Tag" >&2 &&

git tag "${OLD_MULLE_DEV_BRANCH}_squashed" "${OLD_MULLE_DEV_BRANCH}" &&

#
# Now get the new stuff
#
echo "### 5: Checkout" >&2 &&

git checkout -b "${NEW_MULLE_DEV_BRANCH}" "${LLVM_REMOTE}/${NEW_LLVM_BRANCH}" &&

echo "### 6: Cherry pick" >&2 &&

git cherry-pick "tmp_${NEW_MULLE_DEV_BRANCH}" &&

#
# resolve conflicts manually.
# Check with grep '@mulle-objc' ... | wc -l, that all changes are present
#
echo "### 6: Tmp branch delete" >&2 &&

git branch -d "tmp_${NEW_MULLE_DEV_BRANCH}"
