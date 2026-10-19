# Case data licence

The case files in this directory (`case.json`: the labels, notes and other annotations,
and `fetch.sh`) are licensed under
[Creative Commons Attribution 4.0 International (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
Attribute as "ssvc-triage cases".

Parts of each `case.json` are third-party data under their own terms:

- advisory ids, summaries, affected and fixed versions (`facts`) come from
  [OSV](https://osv.dev), including the GitHub Advisory Database, under CC-BY 4.0;
- the applications the cases point at are not included: each `fetch.sh` clones one at a
  pinned commit, under that project's own licence.

The labels (`expect`) were written by AI models reading the code (`labelled_by` records
which, and when); see "Labels and data" in the README.
