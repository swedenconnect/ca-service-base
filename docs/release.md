![Sweden Connect](https://raw.githubusercontent.com/swedenconnect/technical-framework/master/img/sweden-connect.png)

# Releasing

How to make a release of `ca-service-base`. This is for maintainers. Only maintainers can push release tags.

-----

## How a release works

Pushing a tag `vX.Y.Z` starts the [Publish to GitHub Packages](../.github/workflows/maven-github-deploy.yml) workflow. It checks out the tag, checks that the version in `pom.xml` is `X.Y.Z`, builds and tests with the `release` profile, signs the files and deploys them to the GitHub Packages Maven registry of this repository:

```
https://maven.pkg.github.com/swedenconnect/ca-service-base
```

Versions up to 2.0.1 were published to Maven Central and stay there. How users of the library download later versions is described in [Using the Artifacts from GitHub Packages](github-packages.md).

Snapshot versions are not published.

## Make a release

1. Create a release branch from `main`, and set the release version in `pom.xml`, for example `2.0.2` instead of `2.0.2-SNAPSHOT`.
2. Build it with the release profile, without signing:

   ```bash
   mvn -Prelease -Dgpg.skip=true clean install
   ```

   This also builds the source and Javadoc files that are published, so a Javadoc error shows up here and not in the workflow.
3. Commit the version, push the branch and open a pull request into `main`.
4. Create the tag on the release commit, and push it:

   ```bash
   git tag -a v2.0.2 -m "2.0.2"
   git push origin v2.0.2
   ```

   The tag starts publishing. Follow the run under **Actions** in the repository.
5. Merge the pull request.
6. On `main`, set the next snapshot version in `pom.xml`, for example `2.0.3-SNAPSHOT`, and merge that too.

Older releases were tagged `X.Y.Z-release-tag`. Only tags starting with `v` start publishing.

## Rules

- **The version in the POM must match the tag.** The workflow stops before anything is built if the version is a snapshot or differs from the tag.
- **Never release the same version twice.** GitHub Packages refuses to publish a version that is already there, and the versions up to 2.0.1 are on Maven Central, which never lets a published version be replaced.

## Publishing from a developer machine

The `release` profile deploys to GitHub Packages as the server with the id `github`. To deploy without the workflow, add that server to `~/.m2/settings.xml` with a classic personal access token with the `write:packages` scope, and run:

```bash
mvn -Prelease clean deploy
```

This signs with the local `gpg` installation.

## Secrets

The workflow uses the token GitHub gives it to publish, and these secrets for signing:

| Secret | What it is |
|---|---|
| `BOT_GPG_PRIVATE_KEY` | the armored private GPG key used to sign the release files |
| `BOT_GPG_PASSWORD` | the passphrase of that key |

The same token is used to download releases of other Sweden Connect libraries published to GitHub Packages.

## Publishing to Maven Central again

Publishing to Maven Central is kept possible, in case it is needed again. The `maven-central-release` profile, selected together with `release`, replaces the deploy to GitHub Packages with an upload to Maven Central through the Sonatype Central publishing plugin, as the server with the id `central`.

The [Publish to Maven Central](../.github/workflows/maven-central-deploy.yml) workflow does this for a given tag, and can only be started by hand. Besides the GPG secrets it uses:

| Secret | What it is |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | the user name half of a Central portal token |
| `MAVEN_CENTRAL_TOKEN_PASSWORD` | the password half of the same token |

Maven Central does not let a published version be removed or replaced. Publishing a version to both GitHub Packages and Maven Central is fine, since it is the same build of the same tag.
