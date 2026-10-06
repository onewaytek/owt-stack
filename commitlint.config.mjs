// Commit messages and pull request titles follow Conventional Commits, which
// release-please reads to choose the next version and write the changelog.
export default {
  extends: ["@commitlint/config-conventional"],
  // Dependabot's bodies quote release notes, whose lines run past the length limit.
  // Its headers ("fix(deps): bump ...") are generated, and the title check sees them.
  ignores: [(message) => message.includes("Signed-off-by: dependabot[bot]")],
};
