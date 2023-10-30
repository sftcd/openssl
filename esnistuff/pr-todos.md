# Things to do for an ECH PR

Our current branch (ECH-draft-13c) isn't quite right for using to make even a
draft PR for ECH.

## Reasons

- Awaiting final ECH extension codepoint(s) to be allocated, and it's not clear
  for how long we'll need to keep the draft-13 codepoint in the code
- The ``esnistuff`` directory content needs to be moved elsewhere
- ``include/openssl/ech.h`` should be integrated into ``ssl.h``, which means
  minor changes to application integrations
- The ``ech_ext_handling`` tables in ``ssl/ech.c`` should be integrated with
  the ``ext_defs`` table in ``ssl/statem/extensions.c``
- Code behind ``ifdef SUPERVERBOSE`` should probably stay until nearly the last
  minute, then be dropped

Aside from those issues, it'd be great to figure a way to break this all down
into more than one PR, but not sure how to do that.

## Plan

Make a new branch as if we're doing a PR, and backport as many changes as we
can into ECH-draft-13c while moving all the ``esnistuff/`` content we want to
keep for now into a new public repo.

