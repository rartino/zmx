# zmx build and install.
#
#   make build           debug build (fast to compile, safety checks on)
#   make build_release   ReleaseSafe -- what upstream ships; use this to install
#   make install         system-wide install (PREFIX, honours DESTDIR)
#   make install_user    per-user install into XDG directories
#
# ReleaseSafe is deliberate: it keeps bounds and integer-overflow checks on.
# zmx parses untrusted terminal output in a long-lived daemon, so -Doptimize=
# ReleaseFast trades a real safety net for speed you will not notice.

# Zig 0.16.0 is required (see build.zig.zon). Override with: make ZIG=/path/to/zig
ZIG ?= $(firstword $(wildcard ../.venv/lib/python*/site-packages/ziglang/zig) zig)

PREFIX     ?= /usr/local
DESTDIR    ?=
BIN         = zig-out/bin/zmx

# XDG base directories, with the spec's defaults when unset.
XDG_DATA_HOME   ?= $(HOME)/.local/share
XDG_CONFIG_HOME ?= $(HOME)/.config
# Not in the spec, but the de-facto standard location systemd and others use.
XDG_BIN_HOME    ?= $(HOME)/.local/bin

.PHONY: build build_release install install_user test check clean

build:
	$(ZIG) build

build_release:
	$(ZIG) build -Doptimize=ReleaseSafe

test:
	$(ZIG) build test

check:
	$(ZIG) build check

clean:
	rm -rf zig-out .zig-cache

$(BIN):
	@echo "$(BIN) not built. Run: make build_release" >&2
	@exit 1

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/zmx
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	install -d $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	$(BIN) completions bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/zmx
	$(BIN) completions zsh  > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_zmx
	$(BIN) completions fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/zmx.fish
	@echo "installed $(DESTDIR)$(PREFIX)/bin/zmx"

# zmx creates its own runtime and state directories on first run
# ($XDG_RUNTIME_DIR/zmx and $XDG_STATE_HOME/zmx/logs), with the modes it
# wants, so this target deliberately does not pre-create them.
install_user: $(BIN)
	install -d $(XDG_BIN_HOME)
	install -m 0755 $(BIN) $(XDG_BIN_HOME)/zmx
	install -d $(XDG_DATA_HOME)/bash-completion/completions
	install -d $(XDG_DATA_HOME)/zsh/site-functions
	install -d $(XDG_CONFIG_HOME)/fish/completions
	$(BIN) completions bash > $(XDG_DATA_HOME)/bash-completion/completions/zmx
	$(BIN) completions zsh  > $(XDG_DATA_HOME)/zsh/site-functions/_zmx
	$(BIN) completions fish > $(XDG_CONFIG_HOME)/fish/completions/zmx.fish
	@echo "installed $(XDG_BIN_HOME)/zmx"
	@case ":$$PATH:" in *":$(XDG_BIN_HOME):"*) ;; \
	  *) echo "note: $(XDG_BIN_HOME) is not on your PATH" >&2 ;; esac
	@echo "note: zsh completions need $(XDG_DATA_HOME)/zsh/site-functions on \$$fpath" >&2
