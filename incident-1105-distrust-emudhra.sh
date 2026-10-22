#!/bin/sh
# INCIDENT-1105: distrust the eMudhra (emSign) roots and Comodo AAA Certificate Services.
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# The private keys of eight eMudhra intermediate CAs are compromised; they chain to emSign
# ECC Root CA - G3 and, by a cross-sign, to AAA. Run this as root, as the last step of each
# stage that ships, and it takes those roots out of every trust store of the image:
#  1. It turns the roots off in the system store, with the distro's own tool.
#  2. It searches every file for other copies. It changes only files it knows:
#     Python packages' root lists become links to the system bundle (as in
#     cloud#30811) when it has all their other roots (but not in a Lambda code or
#     layer directory, whose zip may keep the link), or else lose the roots; keytool
#     deletes them from Java keystores (JKS, JCEKS and PKCS12, with the password
#     changeit or amazon) and from the cacerts in a JDK's jmods/java.base.jmod, which
#     jlink copies into every runtime it builds; and NSS's libnssckbi.so becomes a link
#     to p11-kit-trust.so. Any other file that holds a root fails the build, untouched.
#  3. It checks again what it found (with --check, it searches and checks only), and
#     fails if anything still trusts a root (each error says what to do), if a tool it
#     needs is missing, if a certificate does not decode, if the system bundle lost
#     USERTrust RSA (Sectigo needs it once AAA is gone), or if it found no CA file.
#     Node.js passes only on a release that blocks the compromised certificates
#     (22.23.4, 24.22.1, 26.12.1 or later), and only with ENV NODE_OPTIONS=--use-openssl-ca,
#     as those releases still carry emSign Root CA - G1; Deno only from 2.9.8; and uv
#     only with native-tls (or system-certs) = true in its system uv.toml.
# It does not look inside archives (jar, zip, wheel); a root it sees in one fails the build.
# INCIDENT_1105_IGNORE="<path> ..." leaves files alone (a path that ends in / is a whole
# directory; for a path with a space in it, put one path on each line); give the reason
# in the PR. A Node.js listed there still needs the NODE_OPTIONS line.
# ROOTS is the list of eero-inc/cloud-terraform#6249 plus each root's first PEM line.
# Any certificate that names eMudhra is distrusted too. To add a root, add a line: a name,
# `openssl x509 -noout -fingerprint -sha256 -in root.pem`, `sed -n 2p root.pem`.
set -eu
export PATH="${PATH:-/usr/local/bin:/usr/bin:/bin}:/usr/local/sbin:/usr/sbin:/sbin" # some images leave sbin out

ROOTS="
comodo-aaa-services-root D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4 MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
emsign-ecc-root-ca-c3 BC:4D:80:9B:15:18:9D:78:DB:3E:1D:8C:F4:F9:72:6A:79:5D:A1:64:3C:A5:F1:35:8E:1D:DB:0E:DC:0D:7E:B3 MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQG
emsign-ecc-root-ca-g3 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
emsign-root-ca-c1 12:56:09:AA:30:1D:A0:A2:49:B9:7A:82:39:CB:6A:34:21:6F:44:DC:AC:9F:39:54:B1:42:92:F2:E8:C8:60:8F MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkG
emsign-root-ca-c2 46:CD:08:3B:47:E8:04:02:02:8D:F4:93:96:0E:A1:9C:85:FE:85:19:50:D5:16:5F:1C:7D:A4:FA:A9:51:E2:F8 MIIFcjCCA1qgAwIBAgIKLwq3aw3LSq8nWDANBgkqhkiG9w0BAQwFADBWMQswCQYD
emsign-root-ca-g1 40:F6:AF:03:46:A9:9A:A1:CD:1D:55:5A:4E:9C:CE:62:C7:F9:63:46:03:EE:40:66:15:83:3D:C8:C8:D0:03:67 MIIDlDCCAnygAwIBAgIKMfXkYgxsWO3W2DANBgkqhkiG9w0BAQsFADBnMQswCQYD
emsign-root-ca-g2 1A:A0:C2:70:9E:83:1B:D6:E3:B5:12:9A:00:BA:41:F7:EE:EF:02:08:72:F1:E6:50:4B:F0:F6:C3:F2:4F:3A:F3 MIIFlTCCA32gAwIBAgILAIZNvw/jXtd9jtgwDQYJKoZIhvcNAQEMBQAwZzELMAkG
"
# The roots' files in the ca-certificates package of Debian, Ubuntu and Alpine (G2 and C2 are not in it).
DEBIAN_ENTRIES="mozilla/Comodo_AAA_Services_root.crt mozilla/emSign_ECC_Root_CA_-_C3.crt mozilla/emSign_ECC_Root_CA_-_G3.crt
mozilla/emSign_Root_CA_-_C1.crt mozilla/emSign_Root_CA_-_G1.crt"
# The first PEM line of USERTrust RSA Certification Authority: it must stay.
USERTRUST_RSA=MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB
# The first PEM lines of TrustCor RootCert CA-1 and Hongkong Post Root CA 1, which Mozilla removed in 2022
# and 2023: a system bundle that still has one is old (a note, not a failure).
STALE="MIIEMDCCAxigAwIBAgIJANqb7HHzA7AZMA0GCSqGSIb3DQEBCwUAMIGkMQswCQYD MIIDMDCCAhigAwIBAgICA+gwDQYJKoZIhvcNAQEFBQAwRzELMAkGA1UEBhMCSEsx"
# "eMudhra", "EMUDHRA", "emudhra" and "Emudhra" in base64, at each of their 3 alignments.
EMUDHRA64="ZU11ZGhy VNdWRo lTXVkaHJh RU1VREhSQ VNVURIUk FTVVESFJB ZW11ZGhyY VtdWRocm lbXVkaHJh RW11ZGhyY FbXVkaHJh"
B64PEM="LS0tLS1CRUdJ|0tLS0tQkVH|tLS0tLUJFR0lO" # "-----BEGIN" in base64, the same way
MEI=$(printf 'MEI\014\013')                    # the start of a PyInstaller archive's cookie
# Programs with a root list that this script can't open: a Nuitka one-file program, and Bazel, whose zip holds
# a JDK (a zip file keeps the names of its files as plain text).
NUITKA=NUITKA_ONEFILE_PARENT
BAZEL=embedded_tools/jdk/lib/security/cacerts
NL='
'

# Report a problem; the check fails at the end. (Not from a pipe: that loses the count.)
problem() {
    echo "incident-1105: ERROR: $*" >&2
    PROBLEMS=$((PROBLEMS + 1))
}

# The awk program of certificates(): join each PEM block's base64, whatever its line width, and print it.
# shellcheck disable=SC2016 # awk's own variables
PEM_AWK='BEGIN { while ((getline s < (work "/needles")) > 0) needle[s] = 1 }
/^[ \t]*-----BEGIN (X509 )?(CERTIFICATE|PKCS7)-----/ {
    on = 1; b = ""; p7 = /PKCS7/; if (!seen++ && mode != "lenient") print ENVIRON["PEM_FILE"] >> (work "/parsed"); next }
on && /^[ \t]*-----END/ {
    on = 0; bad = length(b) % 4 || b ~ /=[^=]/; ok = mode == "all" || p7 || bad
    for (s in needle) if (index(b, s)) ok = 1
    if (ok && !(bad && mode == "lenient")) print b, ENVIRON["PEM_FILE"]; next }
on { gsub(/[^A-Za-z0-9+\/=]/, ""); b = b $0 }'

# Read file names and print the PEM certificates (and PKCS#7 bundles) in them as "<base64> <file>", and list
# the files that have any in $WORK/parsed. With "all", print every one. Otherwise print only those that may be
# distrusted (a root's first line or eMudhra's name is in the base64, a PKCS#7 bundle, or bad base64), so that
# distrusted() decodes few. With "lenient" (files with no root's name or first line in them: source code,
# templates, test data), skip bad base64 too. A base64-encoded PEM (a Kubernetes secret, a .env value) is read too.
certificates() {
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            PEM_FILE=$file awk -v mode="${1:-}" -v work="$WORK" "$PEM_AWK" "$file"
            if [ "${1:-}" != all ] && grep -q -E "$B64PEM" "$file"; then
                grep -o -E "[A-Za-z0-9+/]*($B64PEM)[A-Za-z0-9+/]*=*" "$file" | while IFS= read -r run; do
                    echo "$run" | base64 -d 2> /dev/null || true
                    echo
                done | PEM_FILE=$file awk -v mode=lenient -v work="$WORK" "$PEM_AWK"
            fi
        fi
    done
}

# Print the lines of file $2 (- for stdin) that are not in file $1. (grep -v -f takes an empty $1 to
# match nothing under BusyBox, and everything elsewhere.)
minus() {
    awk -v drop="$1" 'FILENAME == drop { seen[$0] = 1; next } !($0 in seen)' "$1" "$2"
}

# Print base64 certificates read one per line as PEM blocks.
pem() {
    awk '{ print "-----BEGIN CERTIFICATE" "-----"; for (i = 1; i <= length($0); i += 64) print substr($0, i, 64); print "-----END CERTIFICATE" "-----" }'
}

# Read "<base64> <file>" lines and print the distrusted ones: the SHA-256 is in ROOTS, it holds a root's DER
# (a PKCS#7 or DER bundle), or it names eMudhra, in any case. Their base64 is left in $WORK/bad. One that does
# not decode counts as distrusted; its base64 is checked first, as BusyBox's base64 -d takes bad input.
distrusted() {
    sort -u > "$WORK/certs"
    cut -d' ' -f1 "$WORK/certs" | sort -u | while read -r cert; do
        if [ $((${#cert} % 4)) != 0 ] || case $cert in *=*[!=]*) true ;; *) false ;; esac ||
            ! echo "$cert" | base64 -d > "$WORK/der" 2> /dev/null; then
            echo "$cert" | tee -a "$WORK/undecodable"
        elif grep -q -x "$(sha256sum < "$WORK/der" | cut -c1-64)" "$WORK/fingerprints" || LC_ALL=C grep -q -i emudhra "$WORK/der" ||
            od -An -tx1 -v "$WORK/der" | tr -d ' \n' | grep -q -F -f "$WORK/prefixes"; then
            echo "$cert"
        fi
    done > "$WORK/bad"
    grep -F -f "$WORK/bad" "$WORK/certs" || true
}

# The name in ROOTS of the root that certificate or bundle $1 (base64) is or holds.
root_name() {
    if grep -q -x -F "$1" "$WORK/undecodable"; then echo "a certificate that does not decode"; return; fi
    prefix=$(echo "$1" | base64 -d | od -An -tx1 -v | tr -d ' \n' | grep -o -F -f "$WORK/prefixes" | head -n 1)
    grep -F -e "${prefix:-none}" "$WORK/roots" | cut -d' ' -f1 | grep . || echo "an eMudhra certificate"
}

# Is $1 a root list this script may change: the system bundle, or a Python package's copy?
known_bundle() {
    case $1 in
        /etc/ssl/certs/ca-certificates.crt | /etc/ssl/cert.pem | /etc/pki/tls/certs/ca-bundle.crt | /etc/pki/tls/cert.pem | \
            /etc/ssl/ca-bundle.pem | /etc/pki/ca-trust/extracted/pem/*.pem | */certifi/cacert.pem | */botocore/cacert.pem | \
            */requests/cacert.pem | */httplib2/cacerts.txt | */grpc/_cython/_credentials/roots.pem | */boto/cacerts/cacerts.txt | \
            */websocket/cacert.pem) return 0 ;;
    esac
    return 1
}

# Is $1 a file of the system store?
system_file() {
    case $1 in /etc/ssl/* | /etc/pki/*) return 0 ;; esac
    return 1
}

# What to do about file $1, which holds a root and is not a root list this script may change.
advice() {
    case $1 in
        /tmp/tmp*cacert.pem | /var/tmp/tmp*cacert.pem)
            echo "it is a copy of certifi's roots that pip's ensurepip leaves on each python -m venv: delete them" \
                "before this step (RUN rm -f ${1%/*}/tmp*cacert.pem)" ;;
        /tmp/* | /var/tmp/*) echo "it is a leftover temporary file: delete it in the RUN line that makes it, or before this step (RUN rm -f $1)" ;;
        /etc/pki/ca-trust/* | /etc/ssl/* | /usr/local/share/ca-certificates/*)
            echo "it is part of the system store: take the certificate out of /etc/pki/ca-trust/source or" \
                "/usr/local/share/ca-certificates, and run this script after the last package install" ;;
        *) echo "this script changes only the system store, Python packages' root lists, Java keystores and NSS:" \
            "fix it where the file comes from (take the roots out, or point what reads it at the system bundle); only if" \
            "nothing trusts a server with it (a test fixture, a sample), list it in INCIDENT_1105_IGNORE and give the reason in the PR" ;;
    esac
}

# Is file $1 left alone: this script's own work files, the distro's packaged roots (step 1 turns them off),
# p11-kit's blocklist and rejected list, what never ships ($WORK/unshipped), or a link?
skipped() {
    case $1 in
        "$WORK"/* | /usr/share/ca-certificates/* | /usr/share/pki/* | /etc/pki/ca-trust/source/blocklist/* | \
            /etc/pki/ca-trust/source/blacklist/* | /etc/pki/ca-trust/extracted/openssl/*) return 0 ;;
    esac
    while IFS= read -r dir; do
        case $1 in "$dir" | "$dir"/*) return 0 ;; esac
    done < "$WORK/unshipped"
    [ -L "$1" ]
}

# Is file $1 named in INCIDENT_1105_IGNORE ($WORK/ignore: one entry a line, as given and as its real path), or
# in a directory named there (an entry that ends in /)?
ignored() {
    while IFS= read -r entry; do
        case $entry in
            */) case $1 in "$entry"*) return 0 ;; esac ;;
            "$1") return 0 ;;
        esac
    done < "$WORK/ignore"
    return 1
}

# Is text file $1 this script or an add-on? Their second line starts with "# INCIDENT-1105", under any name,
# and they hold no PEM block (a team's own bundle may carry such a note).
own_copy() {
    head -c 200 "$1" | sed -n 2p | grep -q '^# INCIDENT-1105' && ! grep -q -e '-----BEGIN [A-Z0-9 ]*-----' "$1"
}

# Is $1 named like Node.js: node, nodejs, node22, node-18, or a distro's libnode.so.<n>?
node_name() {
    case ${1##*/} in node | nodejs | node[0-9]* | node-[0-9]* | libnode.so.*) return 0 ;; esac
    return 1
}

# The type of the Java keystore whose first 12 bytes are $1 (in hex): JKS, JCEKS, PKCS12 (DER, or BER as Bouncy
# Castle writes it), or Bouncy Castle's own BKS (its certificates are plain DER) and UBER (all encrypted).
# Nothing if it is not one.
keystore_type() {
    case $1 in
        feedfeed*) echo JKS ;;
        cececece*) echo JCEKS ;;
        3080020103* | 3081??020103* | 3082????020103* | 3083??????020103* | 3084????????020103*) echo PKCS12 ;;
        0000000200000014*) echo BKS ;;
        0000000[01]00000014*) echo UBER ;;
    esac
}

# The machine that ELF file $1 is built for (its e_machine field, in hex). /proc/self/exe is od itself.
machine() { od -An -tx1 -j 18 -N 2 "$1" 2> /dev/null | tr -d ' \n'; }

# Write the command lines of this script's ancestors to $WORK/ancestors, one a line, up to kaniko's executor
# if there is one; the executor's arguments go to $WORK/kaniko, one a line.
ancestors() {
    pid=$PPID
    : > "$WORK/ancestors"
    while [ "${pid:-0}" != 0 ] && [ -r "/proc/$pid/cmdline" ]; do
        if [ "$(readlink "/proc/$pid/exe" 2> /dev/null)" = /kaniko/executor ]; then
            tr '\0' '\n' < "/proc/$pid/cmdline" > "$WORK/kaniko"
            return 0
        fi
        { tr '\0' ' ' < "/proc/$pid/cmdline"; echo; } >> "$WORK/ancestors"
        pid=$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/$pid/status" 2> /dev/null)
    done
}

# Print what never ships, which the search leaves out: kaniko's own /kaniko, and every mount point of this
# step but / (a RUN --mount, a CI cache, kaniko's build context; kaniko leaves mount points out of the image).
unshipped() {
    if [ -f "$WORK/kaniko" ]; then echo /kaniko; fi
    if [ -r /proc/self/mountinfo ]; then
        awk '$5 != "/" && $5 !~ "^/(proc|sys|dev)(/|$)" { print $5 }' /proc/self/mountinfo | sed 's/\\040/ /g'
    fi
}

# Shell scripts for batches(), each writing to a file of its own next to the patterns file $0 (lines from one
# pipe could mix). LIST lists the files that hold a string of $0. MARKS prints, for each file, an "@@ <file>"
# line and then each string of $0 that it holds. BusyBox grep is very slow on long runs of zero bytes, so with
# BusyBox a file over 16 MiB is read through tr -s, which squeezes them (MARKS_SQUEEZED).
# shellcheck disable=SC2016 # the inner shell expands them
LIST='LC_ALL=C grep -l -F -f "$0" "$@" > "$(mktemp "$0.XXXXXX")"'
# shellcheck disable=SC2016
MARKS='for f; do echo "@@ $f"; LC_ALL=C grep -a -o -F -f "$0" "$f" | sort -u; done > "$(mktemp "$0.XXXXXX")"'
# shellcheck disable=SC2016
MARKS_SQUEEZED='for f; do echo "@@ $f"; tr -s "\000" < "$f" | LC_ALL=C grep -a -o -F -f "$0" | sort -u; done > "$(mktemp "$0.XXXXXX")"'

# Run shell script $2 (its $0 is $3) on batches of $1 of the regular files that find selects with the rest of
# the arguments (directories, then tests), $JOBS batches at once where xargs can (BusyBox 1.28 and older can't),
# or with find -exec where there is no xargs -0. With --list <file> after $3, on the files in that file (one a line).
batches() {
    size=$1 script=$2 arg=$3
    shift 3
    if [ "$1" = --list ]; then
        case $XARGS in
            parallel) tr '\n' '\000' < "$2" | xargs -0 -n "$size" -P "$JOBS" sh -c "$script" "$arg" ;;
            serial) tr '\n' '\000' < "$2" | xargs -0 -n "$size" sh -c "$script" "$arg" ;;
            *) while IFS= read -r file; do sh -c "$script" "$arg" "$file" < /dev/null; done < "$2" ;;
        esac
        return
    fi
    case $XARGS in
        parallel) find "$@" -print0 | xargs -0 -n "$size" -P "$JOBS" sh -c "$script" "$arg" ;;
        serial) find "$@" -print0 | xargs -0 -n "$size" sh -c "$script" "$arg" ;;
        *) find "$@" -exec sh -c "$script" "$arg" {} + ;;
    esac
}

# Print, and remove, what the batches wrote next to file $1.
results() {
    for file in "$1".*; do
        if [ -f "$file" ]; then
            cat "$file"
            rm -f "$file"
        fi
    done
}

# Read the output of MARKS, and print "<kind> <file>" for each string of $WORK/marks-patterns that a file holds
# (but for this script's own files): nuitka or bazel for theirs, roots for a root's name or first line, and also
# pem for a first line. With "files", print just the names of the files that hold any.
marks() {
    awk -v mode="${1:-}" -v work="$WORK/" -v nuitka="$NUITKA" -v bazel="$BAZEL" 'FILENAME == ARGV[1] { mark[$0] = 1; next }
        FILENAME == ARGV[2] { first[$0] = 1; next } /^@@ / { file = substr($0, 4); own = index(file, work) == 1; next } own { next }
        mode == "files" { if (!seen[file]++) print file; next } !($0 in mark) { next }
        { print ($0 == nuitka ? "nuitka" : $0 == bazel ? "bazel" : "roots"), file } $0 in first { print "pem", file }' \
        "$WORK/marks-patterns" "$WORK/net" -
}

# A keytool to read the system's Java stores with, before the search has found every keytool.
some_keytool() {
    for tool in "${JAVA_HOME:-/none}/bin/keytool" "$(command -v keytool || true)" /usr/lib/jvm/*/bin/keytool /usr/lib/jvm/*/jre/bin/keytool; do
        if [ -x "$tool" ]; then
            echo "$tool"
            return 0
        fi
    done
    return 1
}

# Print the trusted certificates of the Java stores that the distro tool builds from the system store (Red Hat's
# extracted java/cacerts and /etc/pki/java/cacerts, Alpine's and Wolfi's /etc/ssl/certs/java/cacerts), as
# "<store> <sha256> <owner>" lines.
system_java_entries() {
    tool=$(some_keytool) || return 0
    for store in /etc/pki/ca-trust/extracted/java/cacerts /etc/pki/java/cacerts /etc/ssl/certs/java/cacerts; do
        if [ -f "$store" ]; then
            LC_ALL=C.UTF-8 "$tool" -J-Duser.language=en -list -v -keystore "$store" -storepass changeit < /dev/null 2> /dev/null |
                awk -v store="$store" '/^Entry type: / { type = $3 } /^Owner: / { owner = $0 }
                    $1 == "SHA256:" && type == "trustedCertEntry" { gsub(":", "", $2); print store, tolower($2), owner }'
        fi
    done
}

# Print the certificates (base64) of the local sources that the distro tool puts in the system bundle: PEM or DER.
local_certificates() {
    for file in /usr/local/share/ca-certificates/* /usr/local/share/ca-certificates/*/* /etc/pki/ca-trust/source/anchors/* \
        /etc/pki/ca-trust/source/*; do
        if [ -f "$file" ]; then echo "$file"; fi
    done > "$WORK/local-files"
    certificates all < "$WORK/local-files" | cut -d' ' -f1
    while IFS= read -r file; do
        case $(head -c 2 "$file" | od -An -tx1 | tr -d ' \n') in 3082 | 3083) base64 < "$file" | tr -d '\n' && echo ;; esac
    done < "$WORK/local-files"
}

# Step 1: turn the roots off in the system store, with the distro's own tool. The tool rebuilds the system
# bundle and the Java stores made from it, from their sources, so compare them before and after.
fix_system_store() {
    echo "$SYSTEM_BUNDLE" | certificates all | cut -d' ' -f1 | sort -u > "$WORK/before"
    system_java_entries | sort -u > "$WORK/java-before"
    if [ -d /etc/pki/ca-trust/source ] && command -v update-ca-trust > /dev/null; then
        # p11-kit leaves out the certificates in its blocklist directory. Amazon Linux 1 and
        # CentOS 6 may have it switched off; switching it on keeps the old files in backups. (CentOS 6's
        # OpenSSL 1.0.1e then fails Sectigo sites that send the AAA cross-certificate: move off CentOS 6.)
        if grep -q force-enable "$(command -v update-ca-trust)"; then
            update-ca-trust force-enable
            rm -rf /etc/pki/backup-traditional-*
        fi
        update-ca-trust extract # so that the anchors added since the last extract are read too
        # p11-kit 0.23 (CentOS 7, Amazon Linux 2) reads only blacklist, later ones blocklist: write to each there is.
        for dir in /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist; do
            if [ -d "$dir" ]; then echo "$dir"; fi
        done > "$WORK/blocklists"
        if [ ! -s "$WORK/blocklists" ]; then
            mkdir -p /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist
            printf '%s\n' /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist > "$WORK/blocklists"
        fi
        for cert in $(printf '%s\n' /etc/pki/ca-trust/extracted/pem/*.pem | certificates | distrusted | cut -d' ' -f1 | sort -u | minus "$WORK/undecodable" -); do
            name=incident-1105-$(echo "$cert" | base64 -d | sha256sum | cut -c1-16).pem
            root=$(root_name "$cert")
            while IFS= read -r dir; do
                echo "incident-1105: blocking $root in $dir/$name"
                echo "$cert" | pem > "$dir/$name"
            done < "$WORK/blocklists"
        done
        update-ca-trust extract
        # Step 2 would take a root that p11-kit still trusts out of the extracted files, but not out of p11-kit.
        printf '%s\n' /etc/pki/ca-trust/extracted/pem/*.pem | certificates | distrusted > "$WORK/unblocked"
        while read -r cert file; do
            if ! grep -q -x -F "$cert" "$WORK/undecodable"; then
                problem "update-ca-trust still puts $(root_name "$cert") in $file, so p11-kit (and GnuTLS and NSS through it) still" \
                    "trusts it: this image's p11-kit reads another blocklist directory than $(tr '\n' ' ' < "$WORK/blocklists")"
            fi
        done < "$WORK/unblocked"
        tool=update-ca-trust
    elif [ -f /etc/ca-certificates.conf ]; then
        if ! command -v update-ca-certificates > /dev/null; then
            problem "/etc/ca-certificates.conf is here but update-ca-certificates is not, so the system store can't be fixed: reinstall ca-certificates"
            return 0
        fi
        # ca-certificates.conf lists the packaged roots to use; "!name" turns one off. The roots' own names are
        # turned off too, installed or not, so that a later upgrade of an old ca-certificates can't add them.
        { printf '%s\n' /usr/share/ca-certificates/*/*.crt | certificates | distrusted | cut -d' ' -f2-
            echo "$DEBIAN_ENTRIES" | tr ' ' '\n' | sed 's,^,/usr/share/ca-certificates/,'; } | sort -u > "$WORK/off"
        while IFS= read -r file; do
            entry=${file#/usr/share/ca-certificates/}
            if grep -q -x -F "!$entry" /etc/ca-certificates.conf; then continue; fi
            echo "incident-1105: turning off $entry in /etc/ca-certificates.conf"
            { grep -v -x -F -e "$entry" -e "!$entry" /etc/ca-certificates.conf || true; echo "!$entry"; } > "$WORK/conf"
            cat "$WORK/conf" > /etc/ca-certificates.conf
        done < "$WORK/off"
        update-ca-certificates --fresh > /dev/null
        tool=update-ca-certificates
    else
        return 0 # no distro tool: step 2 edits the bundle itself
    fi
    # The tool drops any certificate that was added to the bundle by hand...
    echo "$SYSTEM_BUNDLE" | certificates all | cut -d' ' -f1 | sort -u > "$WORK/after"
    minus "$WORK/after" "$WORK/before" > "$WORK/lost"
    sed 's/$/ lost/' "$WORK/lost" | distrusted > /dev/null
    lost=$(minus "$WORK/bad" "$WORK/lost" | wc -l | tr -d ' ')
    [ "$lost" = 0 ] || problem "$lost certificates in $SYSTEM_BUNDLE are not in what $tool makes of its sources, so it drops them" \
        "(they were added to the file by hand, or the file is older than its sources): put the ones you need in" \
        "/usr/local/share/ca-certificates (Debian, Ubuntu, Alpine) or /etc/pki/ca-trust/source/anchors (Red Hat, Amazon Linux) before this step"
    # ...puts back any that was taken out of it by hand (a local source's certificate is new by right)...
    local_certificates | sort -u > "$WORK/local"
    gained=$(minus "$WORK/before" "$WORK/after" | minus "$WORK/local" - | wc -l | tr -d ' ')
    [ "$gained" = 0 ] || problem "$gained certificates that were not in $SYSTEM_BUNDLE are in it after $tool, which makes it from its" \
        "sources (they were taken out of the file by hand, or the file was older than its sources): to keep one out, turn it off" \
        "before this step, with !<name> in /etc/ca-certificates.conf (Debian, Ubuntu, Alpine) or a copy in /etc/pki/ca-trust/source/blocklist (Red Hat, Amazon Linux)"
    # ...and does the same to the Java stores it makes (a CA imported into them with keytool).
    system_java_entries | sort -u > "$WORK/java-after"
    minus "$WORK/java-after" "$WORK/java-before" |
        awk -v fps="$WORK/fingerprints" 'BEGIN { while ((getline f < fps) > 0) fp[f] = 1 }
            !(($2) in fp) && tolower($0) !~ /emudhra/ { n[$1]++ } END { for (s in n) print n[s], s }' > "$WORK/java-lost"
    : > "$WORK/reported"
    while read -r count store; do
        real=$(readlink -f "$store" 2> /dev/null || echo "$store") # /etc/pki/java/cacerts may be a link to the other
        if grep -q -x -F "$real" "$WORK/reported"; then continue; fi
        echo "$real" >> "$WORK/reported"
        problem "$count certificates in $store are not in what $tool makes of its sources, so it drops them (they were imported" \
            "with keytool, or the store is older than its sources): put the ones you need in /etc/pki/ca-trust/source/anchors" \
            "(Red Hat, Amazon Linux) or /usr/local/share/ca-certificates (Alpine) before this step"
    done < "$WORK/java-lost"
}

# Search every file (hidden ones and those in / too) but what never ships, and list in $WORK/found the ones that
# may hold a root: its name or first PEM line, any PEM or base64-encoded PEM, a PKCS#12 store, or a packed program.
search_image() {
    set --
    for dir in /* /.[!.]* /..?*; do
        case $dir in /proc | /sys | /dev) continue ;; esac
        if [ -e "$dir" ] && [ ! -L "$dir" ] && ! grep -q -x -F "$dir" "$WORK/unshipped"; then set -- "$@" "$dir"; fi
    done
    : > "$WORK/errors"
    status=0
    : > "$WORK/big"
    if command -v find > /dev/null; then
        # Regular files only: BusyBox grep -r hangs on a FIFO. With BusyBox, a file over 16 MiB (a disk image, a
        # sparse file, a big program) is read once, one at a time, for what it holds of all the patterns, which also
        # gives its marks (below). GNU grep is quick on runs of zero bytes, and slow on a pipe with no newline in
        # it (a big single-line JSON file), so it reads every file itself.
        if [ "$GNU_GREP" = 1 ]; then
            batches 256 "$LIST" "$WORK/patterns" "$@" -type f 2>> "$WORK/errors" || true
        else
            batches 256 "$LIST" "$WORK/patterns" "$@" -type f ! -size +16384k 2>> "$WORK/errors" || true
            cp "$WORK/patterns" "$WORK/big-patterns"
            batches 1 "$MARKS_SQUEEZED" "$WORK/big-patterns" "$@" -type f -size +16384k 2>> "$WORK/errors" || true
            results "$WORK/big-patterns" > "$WORK/big"
        fi
        { results "$WORK/patterns" | grep -v -F "$WORK/" || true; marks files < "$WORK/big"; } > "$WORK/found"
    else # GNU grep (see below) skips FIFOs and devices when it recurses
        LC_ALL=C grep -r -l -F -f "$WORK/patterns" "$@" 2>> "$WORK/errors" | grep -v -F "$WORK/" > "$WORK/found" || true
    fi
    # Java's files by name: Java 12 and later encrypt PKCS12 stores and Bouncy Castle's UBER stores are all
    # encrypted, so grep may see no root in them, and a JDK's jmods/java.base.jmod is compressed. Java is in the
    # image if a bin/java, bin/keytool or lib/server/libjvm.so is (a jlink or jpackage runtime may have no bin/).
    if command -v find > /dev/null; then
        find "$@" -type f \( -name keytool -o -name java -o -name libjvm.so -o -name java.base.jmod -o -name cacerts \
            -o -name jssecacerts -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.pkcs12' -o -iname '*.jks' -o -iname '*.jceks' \
            -o -iname '*.bks' -o -iname '*.keystore' -o -iname '*truststore*' \) > "$WORK/named" 2>> "$WORK/errors" || true
    else # Amazon Linux's minimal images have no find; GNU grep can list files by name
        grep -r -l -e '' --include=keytool --include=java --include=libjvm.so --include=java.base.jmod --include=cacerts \
            --include=jssecacerts --include='*.[pP]12' --include='*.[pP][fF][xX]' --include='*.[pP][kK][cC][sS]12' \
            --include='*.[jJ][kK][sS]' --include='*.[jJ][cC][eE][kK][sS]' --include='*.[bB][kK][sS]' \
            --include='*.[kK][eE][yY][sS][tT][oO][rR][eE]' --include='*[tT][rR][uU][sS][tT][sS][tT][oO][rR][eE]*' "$@" > "$WORK/named" 2>> "$WORK/errors" || true
    fi
    grep '/bin/keytool$' "$WORK/named" > "$WORK/keytools" || true
    grep -e '/bin/java$' -e '/bin/keytool$' -e '/libjvm\.so$' "$WORK/named" > "$WORK/javas" || true
    grep '/jmods/java\.base\.jmod$' "$WORK/named" > "$WORK/jmods" || true
    if [ -s "$WORK/javas" ]; then
        grep -v -e '/keytool$' -e '/java$' -e '/libjvm\.so$' -e '/java\.base\.jmod$' "$WORK/named" >> "$WORK/found" || true
        # and the trust stores that the Java options in this step's environment name
        for options in "${JAVA_TOOL_OPTIONS:-}" "${JDK_JAVA_OPTIONS:-}" "${_JAVA_OPTIONS:-}" "${JAVA_OPTS:-}"; do
            printf '%s\n' "$options" | tr ' ' '\n' | sed -n 's,^-Djavax\.net\.ssl\.trustStore=\(/.*\),\1,p'
        done | while IFS= read -r store; do
            if [ -f "$store" ]; then readlink -f "$store" 2> /dev/null || echo "$store"; fi
        done >> "$WORK/found"
    fi
    # Which of the found files hold a root's name or first line ("roots <file>" in $WORK/marks), or are a program
    # whose root list this script can't open ("nuitka <file>", "bazel <file>"): one more read of each but the big ones.
    awk '/^@@ / { print substr($0, 4) }' "$WORK/big" > "$WORK/big-files"
    minus "$WORK/big-files" "$WORK/found" > "$WORK/small"
    if [ "$GNU_GREP" = 1 ]; then
        batches 8 "$MARKS" "$WORK/marks-patterns" --list "$WORK/small" 2>> "$WORK/errors" || true
    else
        batches 8 "$MARKS_SQUEEZED" "$WORK/marks-patterns" --list "$WORK/small" 2>> "$WORK/errors" || true
    fi
    { results "$WORK/marks-patterns"; cat "$WORK/big"; } | marks | sort -u > "$WORK/marks"
    if [ -s "$WORK/errors" ]; then
        cat "$WORK/errors" >&2
        status=2
    fi
    [ "$status" -le 1 ] || problem "could not read every file (see above), so the search is not complete"
}

# Does $WORK/marks say "$1 $2"?
marked() { grep -q -x -F "$1 $2" "$WORK/marks"; }

# Sort the files found into $WORK/texts (text with a root's name or first line: PEM, JSON, source code), pems
# (other PEM files), keystores ("<type> <file>"), ders (DER certificates and bundles) and programs ("<kind>
# <file>": programs and other binary files that hold a root). Node.js files that INCIDENT_1105_IGNORE leaves
# alone go to nodes-ignored (they still need the NODE_OPTIONS line), those that name a root to ignored, and source
# code for other machines to notes.
classify() {
    for list in texts pems keystores ders programs unreadable nodes-ignored ignored notes; do : > "$WORK/$list"; done
    sort -u "$WORK/found" > "$WORK/sorted"
    while IFS= read -r file; do
        if skipped "$file"; then continue; fi
        if [ "${file#/}" = "$file" ] || ! dump=$(od -An -tx1 -v -N 4096 "$file" 2> /dev/null); then
            echo "$file" >> "$WORK/unreadable" # a newline in its name, or a path longer than PATH_MAX
            continue
        fi
        if ignored "$file"; then
            if node_name "$file"; then echo "$file" >> "$WORK/nodes-ignored"; fi
            if marked roots "$file"; then echo "$file" >> "$WORK/ignored"; fi
            continue
        fi
        case $file in
            # Node.js's C header of its roots (libnode-dev), and the iOS root lists of Go 1.17 and older, which
            # Go builds only into programs for Apple devices: source code that no program here reads.
            */node_root_certs.h | */src/crypto/x509/root_darwin*.go | */src/crypto/x509/root_ios*.go)
                echo "$file" >> "$WORK/notes"
                continue
                ;;
        esac
        # shellcheck disable=SC2086 # split the bytes into words
        set -- $dump 0 0 0 0 0 0 0 0 0 0 0 0
        magic=$1$2$3$4$5$6$7$8$9${10}${11}${12}
        case $dump in
            *" 00"*) ;; # it has a NUL byte: below
            *)
                if own_copy "$file"; then continue; fi
                if LC_ALL=C grep -q -F -f "$WORK/roots-patterns" "$file"; then echo "$file" >> "$WORK/texts"; else echo "$file" >> "$WORK/pems"; fi
                continue
                ;;
        esac
        type=$(keystore_type "$magic")
        if [ -n "$type" ] && { [ "$type" != PKCS12 ] || [ -s "$WORK/javas" ]; }; then
            echo "$type $file" >> "$WORK/keystores" # JKS, JCEKS, Bouncy Castle's; with Java, PKCS12
        elif case $magic in 3082* | 3083*) true ;; *) false ;; esac; then
            echo "$file" >> "$WORK/ders" # DER: a certificate, or a PKCS#7 or PKCS#12 bundle
        elif case $magic in 7f454c46*) head -c 1024 "$file" | grep -q -F 'UPX!' ;; *) false ;; esac; then
            echo "upx $file" >> "$WORK/programs"
        elif marked nuitka "$file"; then
            echo "nuitka $file" >> "$WORK/programs"
        elif marked bazel "$file"; then
            echo "bazel $file" >> "$WORK/programs"
        elif marked roots "$file"; then
            kind=roots
            case $file in */cert9.db | */cert8.db) kind=nssdb ;; esac
            # a zip file (PK\3\4), or a tar file ("ustar" at byte 258)
            if [ "${magic#504b0304}" != "$magic" ] || [ "${258:-}${259:-}${260:-}${261:-}${262:-}" = 7573746172 ]; then kind=archive; fi
            echo "$kind $file" >> "$WORK/programs"
        elif case $magic in 7f454c46*) tail -c 8192 "$file" | LC_ALL=C grep -q -F "$MEI" ;; *) false ;; esac &&
            LC_ALL=C grep -q -E -e '\.(pem|crt)' -e cacert "$file"; then
            echo "pyinstaller $file" >> "$WORK/programs" # a PyInstaller one-file program with a root list
        fi
    done < "$WORK/sorted"
}

# Run $KEYTOOL with options "$@" on store $KS of type $TYPE, with the password $PASS (none if it is empty). A
# UTF-8 locale keeps an alias that is not ASCII as it is, on the way out and back in.
keytool_on() {
    if [ -n "$PASS" ]; then set -- "$@" -storepass "$PASS"; fi
    LC_ALL=C.UTF-8 "$KEYTOOL" -J-Duser.language=en "$@" -keystore "$KS" -storetype "$TYPE" < /dev/null
}

# Print the aliases of the distrusted entries in Java keystore $1 of type $2 (JKS, JCEKS or PKCS12): the SHA-256
# is a root's, or the owner names eMudhra. It tries the keytool of the store's JDK ($3, or the one it is in),
# then every other keytool here (an old one can't read a newer store), with the public default passwords
# changeit and amazon (Amazon's trust stores), and sets KEYTOOL and PASS to the ones that opened it. A JKS or
# JCEKS store keeps its certificates in plain DER, so keytool lists it with no password too (PASS is then
# empty, and nothing can be deleted). It fails (1) if none opens it, KEYTOOLS then listing those it tried, or
# (2) if the listing is not in the layout read here (an alias, an entry type and, for a trusted one, a SHA256).
distrusted_aliases() {
    KS=$1 TYPE=$2 KEYTOOLS=
    { echo "${3:-${1%/lib/security/*}}/bin/keytool"; command -v keytool || true; cat "$WORK/keytools"; } > "$WORK/tools"
    while IFS= read -r KEYTOOL; do
        if [ ! -x "$KEYTOOL" ] || case " $KEYTOOLS " in *" $KEYTOOL "*) true ;; *) false ;; esac; then continue; fi
        KEYTOOLS="${KEYTOOLS:+$KEYTOOLS }$KEYTOOL"
        for PASS in changeit amazon ""; do
            if [ -z "$PASS" ] && [ "$TYPE" = PKCS12 ]; then continue; fi
            if keytool_on -list -v > "$WORK/listing" 2>&1; then
                awk -v fps="$WORK/fingerprints" 'BEGIN { while ((getline f < fps) > 0) fp[f] = 1 }
                    /^Alias name: / { alias = substr($0, 13); aliases++ } /^Entry type: / { type = $3; types++; trusted += type == "trustedCertEntry" }
                    /^Owner: / && type == "trustedCertEntry" && tolower($0) ~ /emudhra/ { print alias }
                    $1 == "SHA256:" && type == "trustedCertEntry" { sums++; gsub(":", "", $2); if (tolower($2) in fp) print alias }
                    END { exit aliases != types || sums < trusted }' "$WORK/listing" > "$WORK/listed" || return 2
                sort -u "$WORK/listed"
                return 0
            fi
        done
    done < "$WORK/tools"
    return 1
}

# A JDK's jmods/java.base.jmod $1 holds a copy of cacerts, which jlink copies into every runtime it builds. It is
# a zip file behind a 4-byte header: unpack lib/security/cacerts from it into $WORK/jmod with the JDK's own jar
# (which reads past the header; GraalVM's zip offsets count it), and set JMOD_CACERTS to it and JMOD_TYPE to its
# type. pack_jmod puts it back: jar updates the zip without the header, which then goes back in front.
unpack_jmod() {
    JMOD_CACERTS=$WORK/jmod/lib/security/cacerts
    rm -rf "$WORK/jmod" && mkdir "$WORK/jmod" &&
        (cd "$WORK/jmod" && "${1%/jmods/java.base.jmod}/bin/jar" xf "$1" lib/security/cacerts) && [ -f "$JMOD_CACERTS" ] &&
        JMOD_TYPE=$(keystore_type "$(head -c 12 "$JMOD_CACERTS" | od -An -tx1 | tr -d ' \n')") && [ -n "$JMOD_TYPE" ]
}
pack_jmod() {
    tail -c +5 "$1" > "$WORK/jmod/java.base.zip" &&
        (cd "$WORK/jmod" && "${1%/jmods/java.base.jmod}/bin/jar" ufM java.base.zip lib/security/cacerts) &&
        { head -c 4 "$1" && cat "$WORK/jmod/java.base.zip"; } > "$WORK/jmod/java.base.jmod" && cat "$WORK/jmod/java.base.jmod" > "$1"
}

# Step 2: fix every copy that the search found.
fix_copies() {
    # Python packages ship a copy of the public root list: link it to the system bundle, so it gets later root
    # changes too, but only if the system bundle has every other root of the copy (an old OS can lag behind
    # certifi), and not in a Lambda code or layer directory, whose zip may keep the link, which then points at
    # the Lambda runtime's own bundle. Otherwise, and in the system bundle, delete the roots. A link keeps the
    # file's owner: uv hard-links the files of its cache, which only their owner may do. Step 3 fails the build
    # for any other file that holds a root (this script edits no other file).
    { certificates < "$WORK/texts"; certificates lenient < "$WORK/pems"; } | distrusted | cut -d' ' -f2- > "$WORK/bad-files"
    echo "$SYSTEM_BUNDLE" | certificates all | cut -d' ' -f1 | sort -u > "$WORK/system"
    sort -u "$WORK/bad-files" > "$WORK/fix"
    while IFS= read -r file; do
        if grep -q 'PRIVATE KEY' "$file" || ! known_bundle "$file"; then continue; fi
        case $file in
            /etc/*) ;;
            /var/task/* | /opt/python/* | /opt/nodejs/* | /opt/lib/* | /asset-output/*)
                echo "incident-1105: not linking $file: it is in a Lambda code or layer directory"
                ;;
            *)
                missing=$(echo "$file" | certificates all | cut -d' ' -f1 | minus "$WORK/bad" - | minus "$WORK/system" - | wc -l | tr -d ' ')
                if [ -n "$SYSTEM_BUNDLE" ] && [ "$missing" = 0 ]; then
                    echo "incident-1105: linking $file to $SYSTEM_BUNDLE"
                    # shellcheck disable=SC2012 # only the owner's numbers
                    owner=$(ls -ln "$file" | awk '{ print $3 ":" $4 }')
                    if ! ln -sf "$SYSTEM_BUNDLE" "$file" || { [ "$owner" != 0:0 ] && ! chown -h "$owner" "$file"; }; then
                        problem "could not make $file a link to $SYSTEM_BUNDLE owned by $owner (see above)"
                    fi
                    continue
                fi
                echo "incident-1105: not linking $file: the system bundle lacks $missing of its other roots"
                ;;
        esac
        echo "incident-1105: removing $(grep -c -x -F "$file" "$WORK/bad-files") distrusted certificates from $file"
        echo "$file" | certificates all | cut -d' ' -f1 | minus "$WORK/bad" - | pem > "$WORK/kept"
        cat "$WORK/kept" > "$file" || problem "could not write $file (see above)"
    done < "$WORK/fix"
    # Java keystores, and the cacerts in a JDK's jmods. Bazel takes a store whose time has changed for a damaged
    # one, so a store keeps its time.
    while read -r type keystore; do
        if [ "$type" = BKS ] || [ "$type" = UBER ] || ! distrusted_aliases "$keystore" "$type" > "$WORK/aliases" ||
            [ -z "$PASS" ] || [ ! -s "$WORK/aliases" ]; then continue; fi # step 3 reports it
        touch -r "$keystore" "$WORK/stamp"
        while IFS= read -r alias; do
            echo "incident-1105: deleting $alias from $keystore"
            keytool_on -delete -alias "$alias" || problem "keytool could not delete $alias from $keystore"
        done < "$WORK/aliases"
        touch -r "$WORK/stamp" "$keystore" || problem "could not set the time of $keystore back"
    done < "$WORK/keystores"
    while IFS= read -r jmod; do
        if skipped "$jmod" || ignored "$jmod" || ! unpack_jmod "$jmod" ||
            ! distrusted_aliases "$JMOD_CACERTS" "$JMOD_TYPE" "${jmod%/jmods/java.base.jmod}" > "$WORK/aliases" ||
            [ -z "$PASS" ] || [ ! -s "$WORK/aliases" ]; then continue; fi # step 3 reports it
        while IFS= read -r alias; do
            echo "incident-1105: deleting $alias from the cacerts in $jmod"
            keytool_on -delete -alias "$alias" || problem "keytool could not delete $alias from the cacerts in $jmod"
        done < "$WORK/aliases"
        pack_jmod "$jmod" || problem "could not put the fixed cacerts back into $jmod (see above)"
    done < "$WORK/jmods"
    # NSS's built-in roots (libnssckbi.so, or libnssckbi.so.<n> on Alpine): p11-kit-trust.so is a drop-in
    # replacement that serves the fixed system store. Take the module built for the library's own machine, next
    # to it if there is one (an application's own NSS, a cross-compiling sysroot, a multiarch library).
    grep -E '^roots .*/libnssckbi\.so(\.[0-9]+)*$' "$WORK/programs" | cut -d' ' -f2- > "$WORK/nss" || true
    while IFS= read -r library; do
        dir=${library%/*}
        for module in "${dir%/nss}/pkcs11/p11-kit-trust.so" /usr/lib64/pkcs11/p11-kit-trust.so /usr/lib/pkcs11/p11-kit-trust.so \
            /usr/lib/*/pkcs11/p11-kit-trust.so; do
            if [ -f "$module" ] && [ "$(machine "$module")" = "$(machine "$library")" ]; then
                echo "incident-1105: replacing $library with a link to $module"
                ln -sf "$module" "$library" || problem "could not replace $library with a link to $module"
                break
            fi
        done
    done < "$WORK/nss"
}

# The ENV line that gives Node.js the system store, keeping the image's own NODE_OPTIONS; Red Hat-family and
# Lambda images also need SSL_CERT_FILE.
node_env_line() {
    line="ENV NODE_OPTIONS=--use-openssl-ca"
    if [ -n "${NODE_OPTIONS:-}" ]; then line="ENV NODE_OPTIONS=\"--use-openssl-ca \$NODE_OPTIONS\""; fi
    if [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then line="$line SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt"; fi
    echo "$line"
}

# Does the image's ENV give Node.js --use-openssl-ca (and not --use-bundled-ca)? This step sees the image's ENV
# lines, its ARGs and a "NAME=value" prefix of the RUN line alike, so a RUN line (or any command above this
# script) that sets NODE_OPTIONS itself counts as no: it is lost at run time.
node_flag() {
    case " ${NODE_OPTIONS:-} " in
        *" --use-bundled-ca "*) return 1 ;;
        *" --use-openssl-ca "*) ! grep -q 'NODE_OPTIONS=' "$WORK/ancestors" ;;
        *) return 1 ;;
    esac
}

# Pass Node.js $1 only on a release that blocks the compromised certificates itself (its version is read with
# NODE_OPTIONS emptied: the image's own may need files that come later), and only if the image's ENV gives it
# --use-openssl-ca, so that it uses the fixed system store: those releases still carry emSign Root CA - G1. A
# distro's libnode.so.<n> is checked through the node that loads it.
check_node() {
    node=$1
    case $1 in
        */libnode.so.*)
            for exe in "${1%%/lib*}/bin/node" "${1%%/lib*}/bin/nodejs" "${1%%/lib*}"/bin/node-[0-9]*; do
                if [ "$(NODE_OPTIONS='' "$exe" -p process.versions.modules 2> /dev/null)" = "${1##*.so.}" ]; then
                    node=$exe
                    break
                fi
            done
            ;;
    esac
    if ! version=$(NODE_OPTIONS='' "$node" -v 2> /dev/null); then
        problem "$1 is Node.js, but it does not run here (a missing library or the wrong libc), so its version can't be checked: make it run, or remove it"
    elif ! echo "$version" | awk -F. '{ sub(/^v/, "", $1); a = $1 + 0; b = $2 + 0; c = $3 + 0
        exit !(a > 26 || a == 26 && (b > 12 || b == 12 && c >= 1) || a == 24 && (b > 22 || b == 22 && c >= 1) || a == 22 && (b > 23 || b == 23 && c >= 4)) }'; then
        problem "$1 is Node.js $version, which trusts the compromised certificates: upgrade it to 22.23.4, 24.22.1 or 26.12.1 or later," \
            "with $(node_env_line) before this step. Node.js 20 has no fixed release: move to 22, or set that ENV line, list the file" \
            "in INCIDENT_1105_IGNORE and give the reason in the PR"
    elif ! node_flag; then
        problem "$1 is Node.js $version, which blocks the compromised certificates, but its own copy of the roots still has emSign Root" \
            "CA - G1: add $(node_env_line) before this step (an ENV line: NODE_OPTIONS set in the RUN line is lost at run time)"
    else
        echo "incident-1105: $1 is Node.js $version, which blocks the compromised certificates itself, and uses the system store"
    fi
}

# Is $1 a true value for uv (1, true, yes, on)?
true_value() {
    case $(echo "$1" | tr '[:upper:]' '[:lower:]') in 1 | true | yes | on | y | t) return 0 ;; esac
    return 1
}

# Does uv.toml file $1 set key $3 (an ERE: native-tls, or native-tls|system-certs) to $2 (true or false), above
# its first [table]?
uv_sets() {
    awk -v want="$2" -v key="$3" '/^[[:space:]]*\[/ { exit }
        $0 ~ ("^[[:space:]]*(" key ")[[:space:]]*=[[:space:]]*" want "[[:space:]]*(#.*)?$") { found = 1 }
        END { exit !found }' "$1" 2> /dev/null
}

# Pass uv $1 only if the system uv.toml it reads says native-tls (uv 0.11 and later: system-certs) = true above
# its first [table]. uv reads the first uv/uv.toml in $XDG_CONFIG_DIRS (/etc/xdg if unset), else /etc/uv/uv.toml.
# A UV_ variable can't prove it (an ARG or a RUN-line prefix looks the same as an ENV line), but one that
# turns it off fails the build, and so do UV_NO_CONFIG and a user's uv.toml that turns it off.
check_uv() {
    key=native-tls keys=native-tls # a uv older than 0.11 stops on a system-certs key: it knows only native-tls
    if LC_ALL=C grep -q -F system-certs "$1"; then key=system-certs keys='native-tls|system-certs'; fi
    printf '%s\n' "${XDG_CONFIG_DIRS:-/etc/xdg}" | tr ':' '\n' > "$WORK/xdg"
    conf=
    while IFS= read -r dir; do
        if [ -z "$conf" ] && [ -f "$dir/uv/uv.toml" ]; then conf=$dir/uv/uv.toml; fi
    done < "$WORK/xdg"
    conf=${conf:-/etc/uv/uv.toml}
    off=
    for file in "${XDG_CONFIG_HOME:-/root/.config}/uv/uv.toml" /root/.config/uv/uv.toml /home/*/.config/uv/uv.toml; do
        if [ -f "$file" ] && uv_sets "$file" false 'native-tls|system-certs'; then off=$file; fi
    done
    if ! LC_ALL=C grep -q -F XDG_CONFIG_DIRS "$1"; then
        problem "$1 (uv) has the roots built in, and it is too old to read $conf: upgrade it to 0.5 or later"
    elif true_value "${UV_NO_CONFIG:-}"; then
        problem "$1 (uv) has the roots built in, and UV_NO_CONFIG makes it skip $conf: unset UV_NO_CONFIG"
    elif { [ -n "${UV_NATIVE_TLS:-}" ] && ! true_value "$UV_NATIVE_TLS"; } || { [ -n "${UV_SYSTEM_CERTS:-}" ] && ! true_value "$UV_SYSTEM_CERTS"; }; then
        problem "$1 (uv) has the roots built in, and UV_NATIVE_TLS or UV_SYSTEM_CERTS turns off the system store: unset it"
    elif [ -n "$off" ]; then
        problem "$1 (uv) has the roots built in, and $off turns off the system store: take that line out of it"
    elif ! uv_sets "$conf" true "$keys"; then
        problem "$1 (uv) has the roots built in: put '$key = true' (uv 0.11 renamed native-tls to system-certs) at the" \
            "top of $conf before this step (RUN mkdir -p ${conf%/*} && { echo '$key = true'; cat $conf 2> /dev/null; } >" \
            "$conf.new && mv $conf.new $conf). An ENV UV_NATIVE_TLS or UV_SYSTEM_CERTS can't be checked here, because an" \
            "ARG or a RUN-line prefix looks the same"
    fi
}

# What to do about program $1, which holds the roots, by the runtime built into it (as its own strings show).
check_program() {
    if LC_ALL=C grep -q -F NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1 "$1"; then
        problem "$1 is a Node.js single executable application, which this script can't run to check its Node.js release:" \
            "build it from 22.23.4, 24.22.1 or 26.12.1 or later, with $(node_env_line) in the image, and list it in" \
            "INCIDENT_1105_IGNORE with that reason"
    elif LC_ALL=C grep -q -F d3n0l4nd "$1"; then
        problem "$1 is a program made with deno compile, which this script can't run to check its Deno release: build it with" \
            "Deno 2.9.8 or later, and list it in INCIDENT_1105_IGNORE with that reason"
    elif LC_ALL=C grep -q -F -e '---- Bun! ----' "$1"; then
        problem "$1 is a program made with Bun, which has the roots built in, and no Bun release or setting drops them:" \
            "remove it, or list it in INCIDENT_1105_IGNORE and give the reason in the PR"
    elif LC_ALL=C grep -q -F Electron/ "$1"; then
        problem "$1 is Electron, with its own root list, which this script can't change: remove it, or list it in" \
            "INCIDENT_1105_IGNORE and give the reason in the PR"
    elif LC_ALL=C grep -q -F golang.org/x/crypto/x509roots/fallback "$1"; then
        problem "$1 is a Go program with golang.org/x/crypto/x509roots/fallback, whose roots Go uses only with no system store" \
            "or with GODEBUG=x509usefallbackroots=1: keep the system store, never set that GODEBUG, and list it in" \
            "INCIDENT_1105_IGNORE with that reason"
    elif marked pem "$1"; then
        problem "$1 has the roots built in: upgrade it, rebuild it to use the system store, or remove it"
    else
        problem "$1 names eMudhra or AAA Certificate Services, so it may hold a root as DER, which this script can't check:" \
            "upgrade it, rebuild it to use the system store, or remove it; only if it holds no root (a table of names, a code" \
            "signature, a compiled checker), list it in INCIDENT_1105_IGNORE and give the reason in the PR"
    fi
}

# Step 3: check every copy the search found, and the system store; fail if anything still trusts a root.
check() {
    : > "$WORK/parsed"
    # Every PEM file found, and the system store as TLS libraries read it.
    for file in /etc/ssl/certs/* /etc/ssl/cert.pem /etc/pki/tls/certs/* /etc/pki/tls/cert.pem /etc/pki/ca-trust/extracted/pem/*.pem; do
        if [ -f "$file" ]; then echo "$file"; fi
    done | cat - "$WORK/texts" | certificates > "$WORK/all"
    certificates lenient < "$WORK/pems" >> "$WORK/all"
    while IFS= read -r der; do
        if b64=$(base64 < "$der") && [ -n "$b64" ]; then
            printf '%s %s\n' "$(printf '%s' "$b64" | tr -d '\n')" "$der"
        else
            problem "could not read $der, so it can't be checked"
        fi
    done < "$WORK/ders" >> "$WORK/all"
    distrusted < "$WORK/all" > "$WORK/still"
    files=$(sort -u "$WORK/parsed" | wc -l | tr -d ' ')
    # --check on a stage that never ran the fix: say so once, not for each file of the system store.
    unfixed=
    if [ "$MODE" = check ] && cut -d' ' -f2- "$WORK/still" | grep -q -e '^/etc/ssl/' -e '^/etc/pki/'; then
        unfixed=1
        problem "the system store still trusts the roots: this stage never ran the fix (run this script without --check, after the last package install)"
    fi
    again=
    if [ "$MODE" = check ]; then again=" (run this script without --check, which fixes that file)"; fi
    while read -r cert file; do
        if [ -n "$unfixed" ] && system_file "$file"; then continue; fi
        if known_bundle "$file"; then
            problem "$file trusts $(root_name "$cert")$again"
        else
            problem "$file holds $(root_name "$cert"), and $(advice "$file")"
        fi
    done < "$WORK/still"
    # A root inside JSON or source code, which step 2 cannot remove.
    while IFS= read -r file; do
        if grep -q -F -f "$WORK/net" "$file" && ! cut -d' ' -f2- "$WORK/still" | grep -q -x -F "$file"; then
            problem "$file holds a root in a form this script cannot change (not plain PEM): fix it where it comes from"
        fi
    done < "$WORK/texts"
    while IFS= read -r file; do
        problem "the search found $file, but no tool can open it by that name (a newline in it, or a path over 4096 bytes): rename or remove it"
    done < "$WORK/unreadable"
    if [ -n "$SYSTEM_BUNDLE" ] && ! grep -q -x -F "$USERTRUST_RSA" "$SYSTEM_BUNDLE"; then
        problem "$SYSTEM_BUNDLE lacks USERTrust RSA Certification Authority, so Sectigo sites would fail: update ca-certificates"
    fi
    for start in $STALE; do
        if [ -n "$SYSTEM_BUNDLE" ] && grep -q -x -F "$start" "$SYSTEM_BUNDLE"; then
            echo "incident-1105: note: $SYSTEM_BUNDLE still has roots that Mozilla removed in 2022 and 2023: it is older than its" \
                "package, or copied from an old image or stage; update ca-certificates in the stage that makes it"
            break
        fi
    done
    keystores=0
    while read -r type keystore; do
        if [ -n "$unfixed" ] && system_file "$keystore"; then continue; fi
        keystores=$((keystores + 1))
        if [ "$type" = UBER ]; then
            problem "$keystore is a Bouncy Castle UBER (or BKS-V1) keystore, which is encrypted, so its roots can't be checked:" \
                "fix it where it comes from, or, if it is not a trust store, list it in INCIDENT_1105_IGNORE and give the reason in the PR"
            continue
        elif [ "$type" = BKS ]; then
            if marked roots "$keystore"; then
                problem "$keystore is a Bouncy Castle (BKS) keystore that holds a root, which keytool can't change here: fix it where it" \
                    "comes from, or list it in INCIDENT_1105_IGNORE and give the reason in the PR"
            fi
            continue
        fi
        status=0
        distrusted_aliases "$keystore" "$type" > "$WORK/aliases" || status=$?
        if [ "$status" = 0 ]; then
            :
        elif [ "$status" = 2 ]; then
            problem "$KEYTOOL's listing of $keystore is not in the layout this script reads (Alias name, Entry type, Owner, SHA256):" \
                "the script must be fixed for it; do not list the store in INCIDENT_1105_IGNORE"
        elif [ -z "$KEYTOOLS" ]; then
            problem "$keystore is a Java keystore ($type), and this image has no keytool to check it: keep keytool until this step, or remove the store"
        else
            problem "no keytool here ($KEYTOOLS) can open $keystore as $type with the password changeit or amazon: if it is a trust store," \
                "fix it where it comes from; if it is not (a key store with a password of its own), list it in INCIDENT_1105_IGNORE and give the reason in the PR"
        fi
        why=
        if [ -z "$PASS" ]; then why=": its password is not changeit or amazon, so this script can't delete it: fix it where the store comes from"; fi
        while IFS= read -r alias; do problem "$keystore trusts $alias$why"; done < "$WORK/aliases"
    done < "$WORK/keystores"
    # The cacerts in a JDK's jmods, which jlink copies into every runtime it builds (no program reads it here).
    while IFS= read -r jmod; do
        if skipped "$jmod" || ignored "$jmod"; then continue; fi
        keystores=$((keystores + 1))
        jdk=${jmod%/jmods/java.base.jmod}
        if [ ! -x "$jdk/bin/jar" ]; then
            problem "$jmod holds a cacerts that jlink copies into every runtime it builds, and $jdk has no bin/jar to check it:" \
                "keep jar until this step, or remove the jmods"
        elif ! unpack_jmod "$jmod"; then
            problem "$jdk/bin/jar could not unpack a Java keystore lib/security/cacerts from $jmod (see above), so it can't be checked"
        elif ! distrusted_aliases "$JMOD_CACERTS" "$JMOD_TYPE" "$jdk" > "$WORK/aliases"; then
            problem "no keytool here ($KEYTOOLS) can open the cacerts in $jmod as $JMOD_TYPE with the password changeit or amazon," \
                "or its listing is not in the layout this script reads"
        else
            while IFS= read -r alias; do
                problem "the cacerts in $jmod, which jlink copies into every runtime it builds, trusts $alias"
            done < "$WORK/aliases"
        fi
    done < "$WORK/jmods"
    while IFS= read -r node; do
        if node_flag; then
            echo "incident-1105: leaving $node alone, as INCIDENT_1105_IGNORE asks; the image's NODE_OPTIONS has --use-openssl-ca"
        else
            problem "$node is Node.js, which INCIDENT_1105_IGNORE leaves alone, but it uses its own copy of the roots until the image" \
                "has $(node_env_line): add it before this step (an ENV line: NODE_OPTIONS set in the RUN line is lost at run time)"
        fi
    done < "$WORK/nodes-ignored"
    while IFS= read -r file; do
        case $file in
            */node_root_certs.h) echo "incident-1105: note: leaving $file alone: it is Node.js's C header of its roots, which no program reads" ;;
            *) echo "incident-1105: note: leaving $file alone: Go builds this root list only into programs for Apple devices" ;;
        esac
    done < "$WORK/notes"
    while read -r kind program; do
        if [ -n "$unfixed" ] && system_file "$program"; then continue; fi
        case $kind:${program##*/} in
            archive:*) problem "$program is an archive (zip, jar, wheel or tar) that holds a root, and this script does not change archives:" \
                "fix it where it comes from (a release of what ships it without the root), or list it in INCIDENT_1105_IGNORE and give the reason in the PR" ;;
            upx:*) problem "$program is packed with UPX, so its roots can't be checked: unpack it (upx -d) before this step; or check" \
                "an unpacked copy (upx -d -o <copy> $program before this step: the script then checks the copy), delete the copy," \
                "and list $program in INCIDENT_1105_IGNORE with the result" ;;
            nuitka:*) problem "$program is a Nuitka one-file program, which may carry its own root list, compressed so that this" \
                "script can't check it: build it with --standalone (this script then fixes its certifi), or remove it" ;;
            bazel:*) problem "$program is Bazel, which unpacks its own JDK, whose cacerts trusts the roots, at run time: give that JVM a fixed" \
                "store (startup --host_jvm_args=-Djavax.net.ssl.trustStore=<a store made from the system bundle> in the .bazelrc)," \
                "and list it in INCIDENT_1105_IGNORE with that reason" ;;
            nssdb:*) problem "$program is an NSS database that trusts a root: delete the root from it before this step (certutil -L" \
                "-d sql:${program%/*} lists the nicknames; certutil -D -d sql:${program%/*} -n <nickname> deletes one), or make the database after this step" ;;
            pyinstaller:*) problem "$program is a PyInstaller one-file program with its own root list: build it with --onedir," \
                "so that this script can fix that list, or remove it" ;;
            roots:node | roots:nodejs | roots:node[0-9]* | roots:node-[0-9]* | roots:libnode.so.*) check_node "$program" ;;
            roots:deno)
                version=$("$program" --version 2> /dev/null | sed -n 's/^deno \([0-9.]*\).*/\1/p')
                if [ -z "$version" ]; then
                    problem "$program is Deno, but it does not run here (a missing library or the wrong libc), so its version can't be checked: make it run, or remove it"
                elif echo "$version" | awk -F. '{ exit !($1 > 2 || $1 == 2 && ($2 > 9 || $2 == 9 && $3 >= 8)) }'; then
                    echo "incident-1105: $program is Deno $version, which blocks the compromised certificates itself"
                else
                    problem "$program is Deno $version with the roots built in: upgrade it to 2.9.8 or later"
                fi
                ;;
            roots:bun) problem "$program is Bun, which has the roots built in, and no Bun release or setting drops them (not even" \
                "--use-system-ca): remove it, or list it in INCIDENT_1105_IGNORE and give the reason in the PR" ;;
            roots:uv) check_uv "$program" ;;
            roots:libnssckbi.so | roots:libnssckbi.so.[0-9]*)
                if [ "$(machine "$program")" != "$(machine /proc/self/exe)" ]; then
                    problem "$program is NSS's built-in roots for another machine (a cross-compiling sysroot), and there is no" \
                        "p11-kit-trust.so for that machine to link it to: add one, or, if nothing here loads it, list it in" \
                        "INCIDENT_1105_IGNORE and give the reason in the PR"
                else
                    problem "$program (NSS's built-in roots) must be a link to p11-kit-trust.so: run this script after the last" \
                        "package install, and on Debian, Ubuntu or Alpine install p11-kit-modules or p11-kit-trust first"
                fi
                ;;
            roots:chrome | roots:chromium | roots:chrome-headless-shell | roots:electron | roots:firefox* | roots:libxul.so | roots:omni.ja)
                problem "$program is a browser (or Electron) with its own root list, which this script can't change: remove it," \
                    "or list it in INCIDENT_1105_IGNORE and give the reason in the PR" ;;
            roots:*.[bB][kK][sS]) problem "$program is a Bouncy Castle keystore, which keytool can't open here: fix it where it comes from," \
                "or list it in INCIDENT_1105_IGNORE and give the reason in the PR" ;;
            *:*) if system_file "$program"; then problem "$program holds a root, and $(advice "$program")"; else check_program "$program"; fi ;;
        esac
    done < "$WORK/programs"
    if [ -f "$WORK/kaniko" ] && grep -q -x -e --use-new-run -e --use-new-run=true "$WORK/kaniko"; then
        problem "kaniko --use-new-run does not record the files that this step deletes from the base image, so the fix of the" \
            "system store does not reach the image: build without --use-new-run"
    fi
    echo "incident-1105: checked $files CA files, $keystores Java keystores and $(wc -l < "$WORK/programs" | tr -d ' ') programs"
    [ "$files" != 0 ] || problem "found no CA certificates to check: put this step after ca-certificates is installed"
    count=$(sort -u "$WORK/undecodable" | wc -l | tr -d ' ')
    [ "$count" = 0 ] || problem "$count certificates do not decode, so they can't be checked:" \
        "$(grep -F -f "$WORK/undecodable" "$WORK/certs" | cut -d' ' -f2- | sort -u | head -n 3 | tr '\n' ' ')"
    if [ "$PROBLEMS" != 0 ]; then
        echo "incident-1105: FAILED: see the errors above" >&2
        exit 1
    fi
    if [ -s "$WORK/ignored" ]; then
        echo "incident-1105: note: not checked, as INCIDENT_1105_IGNORE asks, though they name or hold a root: $(tr '\n' ' ' < "$WORK/ignored")"
    fi
    echo "incident-1105: OK: no plain-text, keystore or binary copy of the eMudhra roots or AAA Certificate Services found; archives (jar/zip/whl) not scanned"
}

# Every check depends on these tools; a missing one must fail the build, not skip a check.
for tool in awk base64 cat cut grep head id ln ls mktemp od rm sed sha256sum sort tail tee touch tr wc; do
    if ! command -v "$tool" > /dev/null; then
        echo "incident-1105: ERROR: this image has no $tool, which this script needs: install it before this step" >&2
        exit 1
    fi
done
if ! command -v find > /dev/null && ! grep --version 2> /dev/null | grep -q GNU; then
    echo "incident-1105: ERROR: this image has neither find nor GNU grep, which this script needs to find keystores" >&2
    exit 1
fi
if [ "$(id -u)" != 0 ]; then
    echo "incident-1105: ERROR: run this as root (put it before any USER line)" >&2
    exit 1
fi
PROBLEMS=0
# Its work files, by their real path: /tmp may be a link, and the search lists real paths.
if ! WORK=$(mktemp -d) || ! WORK=$(cd "$WORK" && pwd -P); then
    echo "incident-1105: ERROR: mktemp -d failed: this image needs a writable /tmp (add RUN mkdir -m 1777 /tmp before this step)" >&2
    exit 1
fi
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/undecodable"
MODE=fix
if [ "${1:-}" = --check ]; then MODE=check; fi
GNU_GREP=0
if grep --version 2> /dev/null | grep -q GNU; then GNU_GREP=1; fi
XARGS=none
if command -v xargs > /dev/null && printf 'x\000' | xargs -0 true 2> /dev/null; then
    XARGS=serial
    if printf 'x\000' | xargs -0 -P 2 true 2> /dev/null; then XARGS=parallel; fi # BusyBox 1.28 and older: no -P
fi
JOBS=$(grep -c '^processor' /proc/cpuinfo 2> /dev/null) || JOBS=8 # greps at once: one a CPU, 2 to 16
if [ "$JOBS" -lt 2 ]; then JOBS=2; elif [ "$JOBS" -gt 16 ]; then JOBS=16; fi
echo "$ROOTS" | awk 'NF { gsub(":", "", $2); print tolower($2) }' > "$WORK/fingerprints"
echo "$ROOTS" | awk 'NF { print $3 }' > "$WORK/starts"
# What to search for: the roots' first lines (also as JSON writes them with "\/", PHP's default) and names;
# then any PEM, base64-encoded PEM, PKCS#12 store (by its first content type) or UPX or PyInstaller program.
{ cat "$WORK/starts"; sed -n 's,/,\\/,gp' "$WORK/starts"; } > "$WORK/net"
# (Not "emudhra": this script's own file name has it, in .git/index and the like. A file found for any other
# reason is still checked for the name in any case.)
{ printf '%s\n' eMudhra EMUDHRA Emudhra 'AAA Certificate Services'; cat "$WORK/net"; } > "$WORK/roots-patterns"
{ cat "$WORK/roots-patterns"; printf '%s\n' "$NUITKA" "$BAZEL"; } > "$WORK/marks-patterns"
{ cat "$WORK/marks-patterns"; printf '%s\n' -----BEGIN 'UPX!' "$MEI"; echo "$B64PEM" | tr '|' '\n'
    printf '\006\011\052\206\110\206\367\015\001\007\001\240\n'; } > "$WORK/patterns"
# shellcheck disable=SC2086 # one word per alignment
{ cat "$WORK/starts"; printf '%s\n' $EMUDHRA64; } > "$WORK/needles"
echo "$ROOTS" | while read -r name fingerprint start; do # each root's first 48 bytes in hex, to find it in a bundle
    if [ -n "$name" ]; then echo "$name $(echo "$start" | base64 -d | od -An -tx1 -v | tr -d ' \n') $fingerprint"; fi
done > "$WORK/roots"
cut -d' ' -f2 "$WORK/roots" > "$WORK/prefixes"
ancestors
unshipped > "$WORK/unshipped"
# INCIDENT_1105_IGNORE: paths split at blanks or, when it has more than one line, one path a line; each also by
# its real path, as the search lists files.
case ${INCIDENT_1105_IGNORE:-} in
    *"$NL"*) printf '%s\n' "$INCIDENT_1105_IGNORE" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' ;;
    *) printf '%s\n' "${INCIDENT_1105_IGNORE:-}" | tr '\t' ' ' | tr -s ' ' '\n' ;;
esac | grep . > "$WORK/ignore-given" || true
while IFS= read -r entry; do
    echo "$entry"
    if real=$(readlink -f "$entry" 2> /dev/null) && [ -n "$real" ]; then
        case $entry in */) echo "${real%/}/" ;; *) echo "$real" ;; esac
    fi
done < "$WORK/ignore-given" | sort -u > "$WORK/ignore"
if [ -s "$WORK/ignore-given" ]; then echo "incident-1105: leaving alone, as INCIDENT_1105_IGNORE asks: $(tr '\n' ' ' < "$WORK/ignore-given")"; fi
if [ -f "$WORK/kaniko" ]; then echo "incident-1105: under kaniko: leaving out /kaniko and what is mounted, as kaniko does"; fi
grep -v -x -e /etc/hosts -e /etc/hostname -e /etc/resolv.conf -e /kaniko "$WORK/unshipped" > "$WORK/mounted" || true
if [ -s "$WORK/mounted" ]; then echo "incident-1105: leaving out what is mounted in this step, which never ships: $(tr '\n' ' ' < "$WORK/mounted")"; fi
SYSTEM_BUNDLE=
for file in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [ -f "$file" ]; then
        SYSTEM_BUNDLE=$file
        break
    fi
done
if [ "$MODE" = fix ]; then
    fix_system_store
    search_image
    classify
    fix_copies
else
    search_image
fi
classify # step 3 reads again what the search found: step 2 changes only those files
check
