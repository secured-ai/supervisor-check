# Releasing

Publishing is two steps on purpose. CI stages a tarball; a human approves it
with 2FA. Nothing in this repository can make a release installable on its own.

## Cutting a release

1. Update `CHANGELOG.md` and bump `version` in `package.json`.
2. Merge that to `main`.
3. Publish a GitHub release tagged `v<version>`, matching the version exactly.
   The build job fails if they disagree, before anything is staged.
4. The `Release to npm` workflow runs `typecheck`, `test` and `smoke`, then
   stages the tarball. It prints the approval commands.
5. Approve it from a machine with your npm credentials:

   ```
   npm stage list supervisor-check
   npm stage approve <the id that prints>
   ```

   This asks for 2FA. Until it is approved, nobody can install the release.
   `npm stage reject <id>` throws it away instead.

6. Check the published package actually works, from anywhere:

   ```
   mkdir /tmp/check && cd /tmp/check && npm init -y && npm i supervisor-check@<version>
   node -e "import('supervisor-check').then(m => console.log(Object.keys(m).length, 'exports'))"
   ```

7. Update the install instructions in `README.md`.

## Why `smoke` runs before staging

The suite runs against the source tree, where Node strips types out of `.ts`
files. An installed copy is different in two ways that no test sees: Node
refuses to strip types under `node_modules`, and npm installs a bin as a
symlink. Both produce a package that fails on first use while CI is green.
`npm run smoke` packs the tarball, installs it somewhere with no path back to
this repo, and runs `supervisor-check demo` through the installed bin.

It has already caught one of those: 0.1.0's entry-point guard meant an
installed `supervisor-check` exited 0 and printed nothing.

## One-time setup on npm

The name `supervisor-check` is unscoped, matching `intent-envelope`,
which is already published under the same account.

1. Claim the name, which requires a first publish from a machine with your
   credentials. A trusted publisher cannot be configured for a package that
   does not exist yet.
2. On npmjs.com, under the package's Settings, add a trusted publisher:
   repository `secured-ai/supervisor-check`, workflow `release-npm.yml`,
   environment `npm`.
3. Set the publishing access to **staged only**, so `npm publish` from CI is
   rejected by the registry rather than merely discouraged.
4. In this repository's settings, create an environment named `npm`. It needs
   no secrets: authentication is OIDC. It does not need a required reviewer
   either, because the 2FA approval is the gate and a reviewer here would only
   gate the staging.
