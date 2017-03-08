#!/usr/bin/env bash
#
# Auto-updater && self-invoker
#

set -e  # Work even if somebody does "sh thisscript.sh".

# Colors
red='\e[0;31m'
green='\e[0;32m'
yellow='\e[0;33m'
reset='\e[0m'

echoRed() { echo -e "${red}$1${reset}"; }
echoGreen() { echo -e "${green}$1${reset}"; }
echoYellow() { echo -e "${yellow}$1${reset}"; }

# Basename + usage + argument processing
BASENAME=$(basename $0)
USAGE="Usage: $BASENAME [OPTIONS]
A self-updating wrapper script for the EBSTALL. When run, updates
to both this script and EBSTALL will be downloaded and installed.

Help for ebstall itself cannot be provided until it is installed.

  --debug                                   attempt experimental installation
  -h, --help                                print this help
  -n, --non-interactive,                    run without asking for user input
  --allow-update,                           run without asking on update permission
  --no-self-upgrade                         do not download updates
  --os-packages-only                        install OS dependencies and exit
  -v, --verbose                             provide more output

All arguments are accepted and forwarded to the EBAWS client when run."

# Override of the prompting for update, we dont need it now
ASSUME_YES=1

for arg in "$@" ; do
  case "$arg" in
    --debug)
      DEBUG=1;;
    --os-packages-only)
      OS_PACKAGES_ONLY=1;;
    --no-self-upgrade)
      # Do not upgrade this script (also prevents client upgrades, because each
      # copy of the script pins a hash of the python client)
      NO_SELF_UPGRADE=1;;
    --already-updated)
      ALREADY_UPDATED=1;;
    --help)
      HELP=1;;
    --non-interactive)
      ASSUME_YES=1;;
    --allow-update)
      ALLOW_UPDATE=1;;
    --verbose)
      VERBOSE=1;;
    -[!-]*)
      while getopts ":hnv" short_arg $arg; do
        case "$short_arg" in
          h)
            HELP=1;;
          n)
            ASSUME_YES=1;;
          v)
            VERBOSE=1;;
        esac
      done;;
  esac
done

confirm ()
{
    # call with a prompt string or use a default
    read -r -p "${1:-Are you sure? [y/N]} " response
    RET=0
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Running under root?
if test "`id -u`" -ne "0" ; then
  echo "$USAGE"
  echo ""
  echoRed "Error: This script needs to be run under root."
  echo "Try running with sudo -E -H $0"
  exit 1
fi

if [ "$HELP" == 1 ]; then
    echo "$USAGE"
fi

UPDATE_ALLOWED=0
if [ "$ALLOW_UPDATE" == 1 -o "$ASSUME_YES" == 1 ]; then
    UPDATE_ALLOWED=1
fi

# Can we upgrade? Ask the user
if [ "$ASSUME_YES" != 1 -a "$ALLOW_UPDATE" != 1 ]; then
  echo "EnigmaBridge Installer would like to update itself so you have the newest version"
  if confirm "Do you allow it to do update with pip? [y/N]"; then
    UPDATE_ALLOWED=1
   else
    UPDATE_ALLOWED=0
  fi
fi

# Upgrade step
if [ "$NO_SELF_UPGRADE" != 1 -a "$UPDATE_ALLOWED" == 1 ]; then
    if [ "$ALREADY_UPDATED" != 1 ]; then
        echo "Checking for updates..."
    fi
    set +e

    # Update machine / installer
    if [ "$ALREADY_UPDATED" != 1 ]; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/EnigmaBridge/ebstall-update/ami-01/update.sh)"
        $0 "$@" --already-updated
        exit 1
    fi

    # Update pip trouble maker
    pip install --upgrade appdirs 2>/dev/null >/dev/null

    # Update with pip
    PIP_OUT=`pip install --no-cache-dir --upgrade ebstall 2>&1`
    PIP_STATUS=$?
    set -e

    # Report error. (Otherwise, be quiet.)
    if [ "$PIP_STATUS" != 0 ]; then
      echo "Had a problem while installing Python packages:"
      echo "$PIP_OUT"
      echo ""
      echo "Running the previous version"
    fi
fi

# Invoke the python client directly
SCRIPT=ebstall-pki-cli


if [ -f "/usr/local/bin/${SCRIPT}" ]; then
    /usr/local/bin/${SCRIPT} "$@"
else
    `which ${SCRIPT}` "$@"
fi




