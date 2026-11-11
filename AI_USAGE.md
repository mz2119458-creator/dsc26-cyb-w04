## Tools
I used an AI assistant to generate the initial structure for parsing SARIF and Bandit JSON files, and to help implement the fingerprinting and deduplication logic.

## What AI got wrong
The AI initially implemented the Bandit code line extraction by simply taking the first line of the code block, which failed when a finding was on a different line (e.g., line 9 vs line 10). I noticed this when the test H04 failed, and I fixed it by parsing the line number prefix in each line of the code block to match the line_number.

## In my own words
1. Bandit rates the MD5 in etag() HIGH and DB_PASSWORD LOW. Which would you fix first in Diwan's code, and why?
I would fix the DB_PASSWORD first. Even though Bandit rates it LOW, it is a hard-coded production credential in version control. Anyone with access to the repository can use it to access the production database. The MD5 in etag() is a false positive because it is just a cache key, not used for security.

2. Why does a suppression need an expiry date?
An expiry date ensures that suppressions are reviewed periodically. Without it, a temporary suppression for a false positive could stay in the codebase forever, potentially hiding new, real vulnerabilities that appear in the same line of code later.
