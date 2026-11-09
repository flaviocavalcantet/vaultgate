# The gateway on distroless (M10, TM-7 in docs/threat-model.md), built as the API's
# image is (api/Dockerfile): Python 3.12 and the gateway's dependencies, on a base with
# glibc, OpenSSL and the C++ runtime but no shell and no package manager. Both stages
# are Debian 13, so the libraries copied below match the base's.

FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1
# Debian's security fixes released since the image was built (they reach the copied
# libraries below).
RUN apt-get update --error-on=any && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN python -m venv /venv && /venv/bin/pip install --no-cache-dir .
# What goes into the run stage besides Python and the virtual environment:
# - Python without the standard modules the gateway never imports, whose libraries would
#   come along otherwise (curses, dbm, nis and its Kerberos, readline, sqlite3, crypt,
#   Tk), and without its tests and GUI;
# - the libraries of every Debian package Python and the dependencies link to (glibc,
#   OpenSSL, zlib, ...), from this stage, so with the updates above even when the base
#   image lags them, and their package records, so image scanners see their versions.
# The build fails if a library doesn't resolve or belongs to no package.
RUN set -eu; \
    cd /usr/local/lib/python3.12; \
    rm -rf lib-dynload/_curses*.so lib-dynload/_dbm*.so lib-dynload/_gdbm*.so \
        lib-dynload/nis*.so lib-dynload/readline*.so lib-dynload/_sqlite3*.so \
        lib-dynload/_crypt*.so lib-dynload/_tkinter*.so \
        test idlelib tkinter turtledemo ensurepip sqlite3; \
    libs="$(find /usr/local/bin/python3.12 /usr/local/lib /venv -type f \
        \( -name '*.so*' -o -name python3.12 \) | xargs ldd 2>/dev/null)"; \
    if echo "$libs" | grep 'not found'; then echo "unresolved libraries"; exit 1; fi; \
    pkgs=""; \
    for so in $(echo "$libs" | awk '/=> \//{print $3}' | sort -u); do \
        case "$so" in /usr/local/*|/venv/*) continue ;; esac; \
        real="$(readlink -f "$so")"; \
        pkg="$( (dpkg -S "$real" 2>/dev/null || dpkg -S "/${real#/usr/}" 2>/dev/null) \
            | head -1 | cut -d: -f1)"; \
        [ -n "$pkg" ] || { echo "in no package: $so"; exit 1; }; \
        pkgs="$pkgs $pkg"; \
    done; \
    mkdir -p /runtime/var/lib/dpkg/status.d; \
    for pkg in $(echo $pkgs | tr ' ' '\n' | sort -u); do \
        echo "from Debian: $pkg $(dpkg-query -W -f='${Version}' "$pkg")"; \
        for f in $(dpkg -L "$pkg" | grep '\.so'); do \
            dest="/runtime/usr/${f#/usr/}"; mkdir -p "$(dirname "$dest")"; cp -a "$f" "$dest"; \
        done; \
        dpkg -s "$pkg" > "/runtime/var/lib/dpkg/status.d/$pkg"; \
    done

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /runtime/ /
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /usr/local/bin/python /usr/local/bin/python3 /usr/local/bin/python3.12 /usr/local/bin/
COPY --from=build /venv /venv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LD_LIBRARY_PATH=/usr/local/lib \
    PATH=/venv/bin:/usr/local/bin:/usr/bin:/bin HOME=/tmp
USER 10001
EXPOSE 8888 9100
ENTRYPOINT ["/venv/bin/python", "-m", "vaultgate_gateway.app"]
