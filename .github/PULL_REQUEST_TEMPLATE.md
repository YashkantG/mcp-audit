## What does this change?

<!-- One or two sentences. If it fixes an issue, write "Fixes #123". -->

## Checklist

- [ ] Added a fixture pair (`tests/fixtures/vulnerable_server/`,
      `tests/fixtures/clean_server/`) if this adds or changes a detection rule
- [ ] Added/updated a test asserting the rule fires on the vulnerable fixture
      and doesn't fire on the clean one
- [ ] Updated the Rules table in `README.md` if this adds a new rule ID
- [ ] `pytest -q` passes locally

## Anything reviewers should look at closely?

<!-- Optional — e.g. "not sure this regex handles multi-line strings correctly" -->
