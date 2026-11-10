# Demo

`demo.gif` is generated from `demo.tape` with
[VHS](https://github.com/charmbracelet/vhs).

The recording uses a throwaway key with `--allow-unencrypted`, never authorizes
it, and cleans it up. The key directory is under `/tmp`. If the recording is
interrupted, use the path printed by `start` with
`temp-ssh-key cleanup <path>`; never discover it by globbing.

## Regenerate

`vhs`, `ttyd`, and `ffmpeg` must be on `PATH`. For example:

```sh
# macOS
brew install vhs ttyd ffmpeg

# Ubuntu/Debian; install VHS from its release page or `go install`
sudo apt-get install ttyd ffmpeg

# mise
mise use -g aqua:charmbracelet/vhs aqua:tsl0922/ttyd conda:ffmpeg
```

From the repository root:

```sh
make demo
```

This builds `bin/temp-ssh-key` and writes `demo/demo.gif`. VHS downloads a
headless browser on its first run.
