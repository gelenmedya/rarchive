Archives made with WinRAR, from the `unrar` crate's test data
(https://github.com/muja/unrar.rs, `data/`, MIT OR Apache-2.0).
`comment-hpw-password.rar` has encrypted headers, password `password`.
The RAR 4 ones: `crypted.rar` (password `unrar`; one encrypted compressed member),
`version.rar` (one compressed member), `archive.part1.rar` (the first volume of a set whose
other volumes are not here: it lists, and extraction reports the missing volume).

**Not in the repository** (third-party files). To run the tests that use them, put the files from
the `data/` folder of https://github.com/muja/unrar.rs in this folder; without them those tests skip.
