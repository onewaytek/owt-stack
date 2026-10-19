// Commit messages and pull request titles follow Conventional Commits, which
// release-please reads to choose the next version and write the changelog.
//
// A subject starts lower-case ("fix(web): drop the …"), unless its first word is a
// code identifier: a word with a capital, a digit, an underscore or `::` after its
// first letter (`PUBLIC_URL`, `URL`, `ClientIp`, `S3`, `Sessions::from_env`), or a
// word in backticks. So "fix(deploy): PUBLIC_URL comes only from the params file"
// passes, and "fix(web): Drop the …" and a subject of several words in capitals do
// not. conventional-commits.yml writes the same rules for an app without a
// configuration of its own; the two copies stay identical.
const identifier = /^(`[^`]+`|[A-Za-z][\w:]*([A-Z0-9_]|::)[\w:]*)$/;
export default {
  extends: ["@commitlint/config-conventional"],
  plugins: [
    {
      rules: {
        "subject-first-word": ({ subject }) => {
          const text = subject ?? "";
          const word = text.split(/\s/)[0].replace(/[,;:.]$/, "");
          if (/^[A-Z]/.test(word) && !identifier.test(word)) {
            return [false, "subject must start lower-case, unless its first word is a code identifier"];
          }
          // An identifier may open it, but the rest is prose: some lower case.
          if (/\s/.test(text.trim()) && !/[a-z]/.test(text)) {
            return [false, "subject must not be all capitals"];
          }
          return [true];
        },
      },
    },
  ],
  rules: {
    // The default forbids sentence, start, pascal and upper case, which a subject
    // that starts with (or is) an identifier looks like. `subject-first-word`
    // decides instead: a capital opens a subject only as part of an identifier.
    "subject-case": [0],
    "subject-first-word": [2, "always"],
  },
  // Dependabot's bodies quote release notes, whose lines run past the length limit.
  // Its headers ("fix(deps): bump ...") are generated, and the title check sees them.
  ignores: [(message) => message.includes("Signed-off-by: dependabot[bot]")],
};
