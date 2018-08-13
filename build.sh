#!/usr/bin/env bash

# This script is used to build, and sign a release artifact. See `README.md` for further
# instructions.
#
# Invoke the script with --dev-build in order to skip checks, cleaning and signing.

set -eu

################################################################################
# Verify and configure environment.
################################################################################

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
RUSTC_VERSION=`rustc +stable --version`
PRODUCT_VERSION=$(node -p "require('./package.json').version" | sed -Ee 's/\.0//g')
source env.sh

if [[ "${1:-""}" != "--dev-build" ]]; then

    REQUIRED_RUSTC_VERSION="rustc 1.27.2 (58cc626de 2018-07-18)"

    if [[ $RUSTC_VERSION != $REQUIRED_RUSTC_VERSION ]]; then
        echo "You are running the wrong Rust compiler version."
        echo "You are running $RUSTC_VERSION, but this project requires $REQUIRED_RUSTC_VERSION"
        echo "for release builds."
        exit 1
    fi

    if [[ $(git diff --shortstat 2> /dev/null | tail -n1) != "" ]]; then
        echo "Dirty working directory!"
        echo "You should only build releases in clean working directories in order to make it"
        echo "easier to reproduce the same build."
        exit 1
    fi

    if [[ ("$(uname -s)" == "Darwin") || ("$(uname -s)" == "MINGW"*) ]]; then
        echo "Configuring environment for signing of binaries"
        if [[ -z ${CSC_LINK-} ]]; then
            echo "The variable CSC_LINK is not set. It needs to point to a file containing the"
            echo "private key used for signing of binaries."
            exit 1
        fi
        if [[ -z ${CSC_KEY_PASSWORD-} ]]; then
            read -sp "CSC_KEY_PASSWORD = " CSC_KEY_PASSWORD
            echo ""
            export CSC_KEY_PASSWORD
        fi
        # MacOs: This needs to be set to 'true' to activate signing, even when CSC_LINK is set.
        export CSC_IDENTITY_AUTO_DISCOVERY=true
    else
        unset CSC_LINK CSC_KEY_PASSWORD
        export CSC_IDENTITY_AUTO_DISCOVERY=false
    fi

    cargo +stable clean
else
    echo "!! Development build. Not for general distribution !!"
    GIT_COMMIT=$(git rev-parse --short HEAD)
    PRODUCT_VERSION="$PRODUCT_VERSION-dev-$GIT_COMMIT"

    unset CSC_LINK CSC_KEY_PASSWORD
    export CSC_IDENTITY_AUTO_DISCOVERY=false
fi

echo "Building Mullvad VPN $PRODUCT_VERSION"
SEMVER_VERSION=$(echo $PRODUCT_VERSION | sed -Ee 's/($|-.*)/.0\1/g')

function restore_metadata_backups() {
    mv package.json.bak package.json || true
    mv Cargo.lock.bak Cargo.lock || true
    mv mullvad-daemon/Cargo.toml.bak mullvad-daemon/Cargo.toml || true
    mv mullvad-cli/Cargo.toml.bak mullvad-cli/Cargo.toml || true
    mv mullvad-problem-report/Cargo.toml.bak mullvad-problem-report/Cargo.toml || true
    mv dist-assets/windows/version.h.bak dist-assets/windows/version.h || true
}
trap 'restore_metadata_backups' EXIT

sed -i.bak \
    -Ee "s/\"version\": \"[^\"]+\",/\"version\": \"$SEMVER_VERSION\",/g" \
    package.json

cp Cargo.lock Cargo.lock.bak
sed -i.bak \
    -Ee "s/^version = \"[^\"]+\"\$/version = \"$SEMVER_VERSION\"/g" \
    mullvad-daemon/Cargo.toml \
    mullvad-cli/Cargo.toml \
    mullvad-problem-report/Cargo.toml

SEMVER_ARRAY=($(echo $SEMVER_VERSION | sed -Ee 's/[.-]+/ /g'))
SEMVER_MAJOR=${SEMVER_ARRAY[0]}
SEMVER_MINOR=${SEMVER_ARRAY[1]}
SEMVER_PATCH=${SEMVER_ARRAY[2]}

cp dist-assets/windows/version.h dist-assets/windows/version.h.bak

cat <<EOF > dist-assets/windows/version.h
#define MAJOR_VERSION $SEMVER_MAJOR
#define MINOR_VERSION $SEMVER_MINOR
#define PATCH_VERSION $SEMVER_PATCH
#define PRODUCT_VERSION "$PRODUCT_VERSION"
EOF

################################################################################
# Compile and link all binaries.
################################################################################

if [[ "$(uname -s)" == "MINGW"* ]]; then
    CPP_BUILD_MODES="Release" ./build_windows_modules.sh $@
fi

echo "Building Rust code in release mode using $RUSTC_VERSION..."
cargo +stable build --release

################################################################################
# Other work to prepare the release.
################################################################################

# Only strip binaries on platforms other than Windows.
if [[ "$(uname -s)" != "MINGW"* ]]; then
    binaries=(
        ./target/release/mullvad-daemon
        ./target/release/mullvad
        ./target/release/problem-report
    )
    for binary in ${binaries[*]}; do
        echo "Stripping debugging symbols from $binary"
        strip $binary
    done
fi

echo "Updating relay list..."
set +e
read -d '' JSONRPC_CODE <<-JSONRPC_CODE
var buff = "";
process.stdin.on('data', function (chunk) {
    buff += chunk;
})
process.stdin.on('end', function () {
    var obj = JSON.parse(buff);
    var output = JSON.stringify(obj.result, null, '    ');
    process.stdout.write(output);
})
JSONRPC_CODE
set -e

curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "id": "0", "method": "relay_list"}' \
     https://api.mullvad.net/rpc/  | \
node -e "$JSONRPC_CODE" >  dist-assets/relays.json

echo "Installing JavaScript dependencies..."
cd gui
yarn install

################################################################################
# Package release.
################################################################################

echo "Packing final release artifact..."
case "$(uname -s)" in
    Linux*)     yarn workspace desktop pack:linux;;
    Darwin*)    yarn workspace desktop pack:mac;;
    MINGW*)     yarn workspace desktop pack:win;;
esac

cd ..

for semver_path in dist/*$SEMVER_VERSION*; do
    product_path=$(echo $semver_path | sed -Ee "s/$SEMVER_VERSION/$PRODUCT_VERSION/g")
    echo "Moving $semver_path -> $product_path"
    mv $semver_path $product_path
done

echo "**********************************"
echo ""
echo " The build finished successfully! "
echo " You have built:"
echo ""
echo " $PRODUCT_VERSION"
echo ""
echo "**********************************"
