# Things to do for an ECH PR

Our current branch (ECH-draft-13c) isn't quite right for using to make a
PR for ECH.

## Reasons

- The ``esnistuff`` directory content needs to be moved elsewhere
- ``include/openssl/ech.h`` should be integrated into ``ssl.h.in``, which
  means minor changes to application integrations
- The ``ech_ext_handling`` tables in ``ssl/ech.c`` should in the end be
  integrated with the ``ext_defs`` table in ``ssl/statem/extensions.c``
- Code behind ``ifdef SUPERVERBOSE`` should probably stay until nearly the last
  minute, then be dropped

Aside from those issues, it'd be great to figure a way to break this all down
into more than one PR, but can't see a way to do that.

## Plan

- Create a new ``ech-utils`` repo that gets all the ``esnistuff`` scripts
  we may want to keep, but that shouldn't be in the PR
- "Promote" the current ECH code-points to being the "official" ones as soon
  as the early IANA code-point registration thing is done.
- Everything else to happen in a new branch for the PR.
- Integrate ``ech.h`` into ``ssl.h.in`` (we'll later have to re-do all the
  integrations that included ``ech.h``, but that's only a timing tweak)
- (Maybe) integrate the new function pointers into the ``ext_defs`` table
  in ``extensions.c``? (Might be better done later, not sure - could be
  better to get review of compile-time handling of which extensions to
  ECH-modify/copy/compress, and that may be easier with the new table in
  ``ech.h`` rather than merging into ``ext_defs`` first.)
- (Somehow?) Squash all the dev commits, and then do some rebasing so
  that the PR ends up with a small number of separate commits to help
  reviewers have more easily consumed chunks for examination. The set
  of commits in the initially-submitted PR might then end up as:
    - docs: the ECH API design doc + pod files
    - CLI: command line additions
    - modified internals: existing files where we add some ECH internal API calls
    - new internals: ``ech.c`` and co
    - tests: new test code
- That'll get messy as review comments are handled, but probably anything
  will, so maybe that's ok?

The above will probably take a couple of attempts before we're at the point
where we want to actually open the PR, so trying it out will be a thing.

## Recipe

Possible recipe to do the above, just after rebasing, if our PR branch were to
be ``prb``:

            $ git checkout ECH-draft-13c # dev branch
            $ git checkout -b prb # new branch
            $ git reset --soft master # "uncommit" changes (leaving files as-is)
            $ git restore --staged . # make changes ready for add/commit
            # delete stuff not needed, git add stuff wanted, when checkpoint reached
            $ git commit -m "commit message"
            # repeat above 'till all done, then
            $ git push -u origin prb

The order in which to do commits needs a bit of work.  I still need to figure
the way to distribute the added/modified file changes between commits sensibly.


