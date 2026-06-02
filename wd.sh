#!/usr/bin/env bash
# Author: Alessandro Astone <ales.astone@gmail.com>
# Author: Czarek Nakamoto <cyjan@mrcyjanek.net>
# Source: https://gist.github.com/aleasto/905154449bedb496054593363f074796
set -e

if [ -n "$1" ]; then
    UPSTREAM_CODENAME="$1"
else
    if [ -e /etc/os-release ]; then
        OS_RELEASE=/etc/os-release
    elif [ -e /usr/lib/os-release ]; then
        OS_RELEASE=/usr/lib/os-release
    fi

    UPSTREAM_CODENAME=$(grep "^UBUNTU_CODENAME=" ${OS_RELEASE} | cut -d'=' -f2)

    if [ -z "${UPSTREAM_CODENAME}" ]; then
        UPSTREAM_CODENAME=$(grep "^DEBIAN_CODENAME=" ${OS_RELEASE} | cut -d'=' -f2)
    fi

    if [ -z "${UPSTREAM_CODENAME}" ]; then
        UPSTREAM_CODENAME=$(grep "^VERSION_CODENAME=" ${OS_RELEASE} | cut -d'=' -f2)
    fi

    # Debian 12+
    if [ -z "${UPSTREAM_CODENAME}" ] && [ -e /etc/debian_version ]; then
        UPSTREAM_CODENAME=$(cut -d / -f 1 /etc/debian_version)
    fi

    if [ -z "${UPSTREAM_CODENAME}" ]; then
        echo "[!] Could not detect your distribution. Please provide a valid option as first argument"
        exit 1
    fi
fi

# Remap
#if [ "${UPSTREAM_CODENAME}" = "kinetic" ]; then
#    UPSTREAM_CODENAME="ubuntu-devel"
#fi

# Catch
if ! [[ "${UPSTREAM_CODENAME}" =~ ^(mantic|focal|jammy|kinetic|lunar|noble|oracular|plucky|questing|resolute|buster|bookworm|bullseye|trixie|sid|landing|crimson|byzantium|amber)$ ]]; then
    echo "[!] Distribution \"${UPSTREAM_CODENAME}\" is not supported"
    exit 1
fi

curl --progress-bar --proto '=https' --tlsv1.2 -Sf https://repo.waydro.id/waydroid.gpg --output /usr/share/keyrings/waydroid.gpg
echo "deb [signed-by=/usr/share/keyrings/waydroid.gpg] https://repo.waydro.id/ ${UPSTREAM_CODENAME} main" | tee /etc/apt/sources.list.d/waydroid.list
apt update
