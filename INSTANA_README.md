# Introduction

The current README contains info for the instana downstream located at
https://github.com/instana/opentelemetry-ebpf-profiler

## Downstream management

Since the activity on the upstream is frequent, it is good practise to synch with the upstream frequently, best if it is done maximum every 30 or 45 days.
Currently instana doesn't have an automation for the synch.

The synch and the resolution of merge conflicts is done manually.

## Synch with upstream

Follow these steps:

1. Add the upstream's remote to your remotes' list.

`git remote add upstream git@github.com:open-telemetry/opentelemetry-ebpf-profiler.git`

You can verify the remotes' list with the command `git remote -v`.
The result must be:

```
origin  git@github.com:instana/opentelemetry-ebpf-profiler.git (fetch)
origin  git@github.com:instana/opentelemetry-ebpf-profiler.git (push)
upstream        git@github.com:open-telemetry/opentelemetry-ebpf-profiler.git (fetch)
upstream        git@github.com:open-telemetry/opentelemetry-ebpf-profiler.git (push)
```

2. Align your local index with the upstream's remote objects and refs:
`git fetch upstream --prune`
Alternatively refresh your index for all the remotes:
`git fetch --all --prune`

3. Start the synch in a different branch
Checkout the local branch main, with HEAD origin/main:
`git checkout main`
Be sure you have all the recent updates:
`git pull`
Checkout from `main` a new branch where you will work at the merge with the recent changes in the upstream.
Be sure to give to this branch a significant name, such as `synch_<year>_<n>_wip` where <year> is the current year and <n> is the next ordinal number to identify the synch.
The command will be something like
`git checkout -b synch_2025_01_wip`
Now you are ready to merge the upstream's `main` branch into this branch.
Before doing this, be sure to have the following directories ready somewhere else:
 - A local clone of instana's opentelemtry-ebpf-profiler
 - A local clone of the upstream's opentelemtry-ebpf-profiler
In this way you can always browse these directories without touching the current directory or getting confused saving partial merges, if not necessary.
Run this command to start the merge of the upstream's `main` branch into the `synch_<year>_<n>_wip` branch:
`git merge upstream/main`
It is very likely that you will receive a list of conflicts: be sure to copy past this list and save it on an ASCII text file.

4. Solve conflicts
To solve a conflict, open the file with the conflict. The "HEAD" is the content of the downstream `synch_<year>_<n>_wip` branch, the other stream comes from the upstream's `main` branch.
Once you identify what is the correct content of the file, save the file and run
`git add <file>
when you solved all the conflicts, you are ready to finalize your Merge. If you are not able to solve all the conflicts, go to "partial merges" section.

5. How to finalize your merge
Before doing this, be sure to have the following directory ready somewhere else:
 - A local clone of the upstream's opentelemtry-ebpf-profiler
Execute
`git push`
if it is needed, execute
`git push --force origin synch_2025_01_wip`
Be careful when you format the Merge Message.
Format the first line of the commit message as `Sync from upstream (yeah-month-day)`
Format the body of the message as a list of commit messages, coming from the upstream. Be sure to mention Author and Co-author, for every commit.
You can view this info executing the following command on the local clone of the upstream's opentelemtry-ebpf-profiler:
`git log --pretty=format:"%an <%ae> %s %nCo-authored-by: %cN <%cE>"`
Explanation of formatting
%an: Author name
%ae: Author email
%s: Commit message
%cN: Co-author name
%cE: Co-author email
This format shows the commit hash, author, and commit message, and if there are co-authors, it will display them under "Co-authored-by".

6. Open a PR from branch `synch_2025_01_wip`.
When manual testing is finished and the Pr is approved and merged on `main`, you are ready to create a synch tag.

7. Create the tag of the latest synch commit.

Checkout the local branch main, with HEAD origin/main:
`git checkout main`
Be sure you have all the recent updates:
`git pull`
```
git tag -a synch_<year>_<n> -m "Synch <year> number <n>"
git push origin <tag-name>
```

## Merge Binary Files

To resolve the merge conflict by choosing the upstream version for binary files, follow these steps:

1. Checkout the upstream version:

`git checkout --theirs -- path/to/binary/file`

2. Add the resolved files:

`git add path/to/binary/file`

## Partial Merges

When merging from the upstream, there can be so many complicated conflicts in one commit, that you prefer to stop merging and continue later on after checking more indepently how to re-apply the conflicting commit. But the problem with aborting a merge after you solved a few conflicting commits already is that you “lose” the work you did on fixing those. To not lose partial work, you can "Partially rebase your tree".

You have fixed already a few conflicting commits, but then you hit a big conflict and want to stop the merge. To save your rebase progress, you need to just save your current HEAD.
So from this very point, create a branch:
```
git branch synch_<year>_<n>_partial
```
