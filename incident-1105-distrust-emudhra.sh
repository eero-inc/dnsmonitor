#!/bin/sh
# INCIDENT-1105: distrust the eMudhra (emSign) roots and Comodo AAA Certificate
# Services in every trust store of an image. The private keys of eight eMudhra
# intermediate CAs are compromised; they chain to emSign ECC Root CA - G3 and, by a
# cross-sign, to AAA. Run it as root, as the last step of each stage that ships:
#  1. It turns the roots off in the system store, with the distro's own tool.
#  2. It searches every file for other copies, and fixes them: Python packages'
#     bundles become links to the system bundle (as in cloud#30811), other PEM
#     files lose the roots, keytool deletes them from Java keystores, and NSS's
#     libnssckbi.so becomes a link to p11-kit-trust.so. (A JDK's java.base.jmod,
#     which only jlink reads, is left to incident-1105-distrust-emudhra-jmod.sh.)
#  3. It searches again (with --check, it only does this), and fails if anything
#     still trusts a root (each error says what to do), if the system bundle lost
#     USERTrust RSA (Sectigo needs it once AAA is gone), or if it found no CA file.
# ROOTS is the list of eero-inc/cloud-terraform#6249 plus each root's first PEM
# line. Any certificate that names eMudhra is distrusted too. To add a root, add a
# line: a name, `openssl x509 -noout -fingerprint -sha256 -in root.pem`, `sed -n 2p root.pem`.
set -eu

ROOTS="
comodo-aaa-services-root D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4 MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
emsign-ecc-root-ca-c3 BC:4D:80:9B:15:18:9D:78:DB:3E:1D:8C:F4:F9:72:6A:79:5D:A1:64:3C:A5:F1:35:8E:1D:DB:0E:DC:0D:7E:B3 MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQG
emsign-ecc-root-ca-g3 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
emsign-root-ca-c1 12:56:09:AA:30:1D:A0:A2:49:B9:7A:82:39:CB:6A:34:21:6F:44:DC:AC:9F:39:54:B1:42:92:F2:E8:C8:60:8F MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkG
emsign-root-ca-c2 46:CD:08:3B:47:E8:04:02:02:8D:F4:93:96:0E:A1:9C:85:FE:85:19:50:D5:16:5F:1C:7D:A4:FA:A9:51:E2:F8 MIIFcjCCA1qgAwIBAgIKLwq3aw3LSq8nWDANBgkqhkiG9w0BAQwFADBWMQswCQYD
emsign-root-ca-g1 40:F6:AF:03:46:A9:9A:A1:CD:1D:55:5A:4E:9C:CE:62:C7:F9:63:46:03:EE:40:66:15:83:3D:C8:C8:D0:03:67 MIIDlDCCAnygAwIBAgIKMfXkYgxsWO3W2DANBgkqhkiG9w0BAQsFADBnMQswCQYD
emsign-root-ca-g2 1A:A0:C2:70:9E:83:1B:D6:E3:B5:12:9A:00:BA:41:F7:EE:EF:02:08:72:F1:E6:50:4B:F0:F6:C3:F2:4F:3A:F3 MIIFlTCCA32gAwIBAgILAIZNvw/jXtd9jtgwDQYJKoZIhvcNAQEMBQAwZzELMAkG
"
USERTRUST_RSA=MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB    # its first PEM line: it must stay

# Report a problem; the check fails at the end. (Not from a pipe: that loses the count.)
problem() {
    echo "incident-1105: ERROR: $*" >&2
    PROBLEMS=$((PROBLEMS + 1))
}

# Read file names and print each PEM certificate in them as "<base64> <file>".
certificates() {
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            awk '/^-----BEGIN CERTIFICATE/ { on = 1; b = "" } on && !/^-----/ { gsub(/[^A-Za-z0-9+\/=]/, ""); b = b $0 } on && /^-----END CERTIFICATE/ { print b, FILENAME; on = 0 }' "$file"
        fi
    done
}

# Read "<base64> <file>" lines and print the distrusted ones: the SHA-256 is in
# ROOTS, or the certificate names eMudhra. Their base64 is left in $WORK/bad.
distrusted() {
    sort -u > "$WORK/certs"
    cut -d' ' -f1 "$WORK/certs" | sort -u | while read -r cert; do
        echo "$cert" | base64 -d > "$WORK/der" 2> /dev/null || true
        if grep -q -x "$(sha256sum < "$WORK/der" | cut -c1-64)" "$WORK/fingerprints" || grep -q eMudhra "$WORK/der"; then
            echo "$cert"
        fi
    done > "$WORK/bad"
    grep -F -f "$WORK/bad" "$WORK/certs" || true
}

# The name in ROOTS of a certificate (base64 in $1), found by its first PEM line.
root_name() {
    echo "$ROOTS" | grep -F -e "$(echo "$1" | cut -c1-64)" | cut -d' ' -f1 | grep . || echo "an eMudhra certificate"
}

# Step 1: turn the roots off in the system store, with the distro's own tool.
fix_system_store() {
    if [ -d /etc/pki/ca-trust/source ] && command -v update-ca-trust > /dev/null; then
        # p11-kit leaves out the certificates in its blocklist directory. Amazon Linux 1 and
        # CentOS 6 may have it switched off; switching it on keeps the old files in backups.
        if grep -q force-enable "$(command -v update-ca-trust)"; then
            update-ca-trust force-enable
            rm -rf /etc/pki/backup-traditional-*
        fi
        blocklist=/etc/pki/ca-trust/source/blocklist
        [ -d "$blocklist" ] || blocklist=/etc/pki/ca-trust/source/blacklist
        for cert in $(printf '%s\n' /etc/pki/ca-trust/extracted/pem/*.pem | certificates | distrusted | cut -d' ' -f1 | sort -u); do
            file=$blocklist/incident-1105-$(echo "$cert" | base64 -d | sha256sum | cut -c1-16).pem
            echo "incident-1105: blocking $(root_name "$cert") in $file"
            printf '%s\n' -----BEGIN\ CERTIFICATE----- "$(echo "$cert" | fold -w 64)" -----END\ CERTIFICATE----- > "$file"
        done
        update-ca-trust extract
    elif [ -f /etc/ca-certificates.conf ] && command -v update-ca-certificates > /dev/null; then
        # ca-certificates.conf lists the packaged roots to use; "!name" turns one off.
        printf '%s\n' /usr/share/ca-certificates/*/*.crt | certificates | distrusted | cut -d' ' -f2- | sort -u > "$WORK/off"
        while IFS= read -r file; do
            entry=${file#/usr/share/ca-certificates/}
            if grep -q -x -F "!$entry" /etc/ca-certificates.conf; then continue; fi
            echo "incident-1105: turning off $entry in /etc/ca-certificates.conf"
            { grep -v -x -F -e "$entry" -e "!$entry" /etc/ca-certificates.conf || true; echo "!$entry"; } > "$WORK/conf"
            cat "$WORK/conf" > /etc/ca-certificates.conf
        done < "$WORK/off"
        update-ca-certificates --fresh > /dev/null
    fi
}

# Search every file for a copy of a root (its PEM, or its name in a binary
# copy), and sort what is found into $WORK/texts, keystores and programs.
search_image() {
    set --
    for dir in /*; do
        case $dir in /proc | /sys | /dev) continue ;; esac
        if [ -d "$dir" ] && [ ! -L "$dir" ]; then set -- "$@" "$dir"; fi
    done
    status=0
    grep -r -l -F -f "$WORK/patterns" "$@" > "$WORK/found" || status=$?
    [ "$status" -le 1 ] || problem "grep could not read every file (see above), so the search is not complete"
    : > "$WORK/texts"; : > "$WORK/keystores"; : > "$WORK/programs"
    while IFS= read -r file; do
        case $file in
            # This script, the distro's packaged roots (step 1 turns them off), p11-kit's blocklist and its rejected list.
            "$WORK"/* | */incident-1105-distrust-emudhra*.sh | /usr/share/ca-certificates/* | /usr/share/pki/* | \
                /etc/pki/ca-trust/source/blocklist/* | /etc/pki/ca-trust/source/blacklist/* | /etc/pki/ca-trust/extracted/openssl/*)
                continue ;;
        esac
        case " ${INCIDENT_1105_IGNORE:-} " in *" $file "*) continue ;; esac
        if [ -L "$file" ]; then
            continue
        elif ! head -c 4096 "$file" | od -An -tx1 | grep -q ' 00'; then
            echo "$file" >> "$WORK/texts"    # no NUL byte
        elif [ "$(head -c 4 "$file" | od -An -tx1 | tr -d ' \n')" = feedfeed ] || [ "${file##*/}" = cacerts ]; then
            echo "$file" >> "$WORK/keystores"    # a JKS file, or named cacerts
        else
            echo "$file" >> "$WORK/programs"
        fi
    done < "$WORK/found"
}

# Print the aliases of the distrusted entries in Java keystore $1, with its JDK's keytool or any
# other (-keystore works on Java 8 too). Fail if it can't open it with the password changeit.
distrusted_aliases() {
    KEYTOOL=${1%/lib/security/*}/bin/keytool
    [ -x "$KEYTOOL" ] || KEYTOOL=$(command -v keytool) || return 1
    "$KEYTOOL" -J-Duser.language=en -list -v -keystore "$1" -storepass changeit < /dev/null > "$WORK/listing" 2>&1 || return 1
    awk '/^Alias name: / { alias = substr($0, 13) } /^Entry type: / { type = $3 } /^Owner: / { owner = $0 } $1 == "SHA256:" && type == "trustedCertEntry" { gsub(":", "", $2); print alias "|" tolower($2) "|" owner }' "$WORK/listing" |
        grep -F -e eMudhra -f "$WORK/fingerprints" | cut -d'|' -f1 | sort -u
}

# Step 2: fix every copy that the search found.
fix_copies() {
    # Python packages ship a copy of the public root list: link it to the system bundle, so it
    # gets later root changes too. Other PEM files lose the roots (one with a key is left to step 3).
    certificates < "$WORK/texts" | distrusted | cut -d' ' -f2- > "$WORK/bad-files"
    while IFS= read -r file; do
        count=$(grep -c -x -F "$file" "$WORK/bad-files" || true)
        if [ "$count" = 0 ] || grep -q 'PRIVATE KEY' "$file"; then continue; fi
        case $file in
            */certifi/cacert.pem | */botocore/cacert.pem | */requests/cacert.pem | */httplib2/cacerts.txt | */grpc/_cython/_credentials/roots.pem)
                if [ -n "$SYSTEM_BUNDLE" ]; then
                    echo "incident-1105: linking $file to $SYSTEM_BUNDLE"
                    ln -sf "$SYSTEM_BUNDLE" "$file"
                    continue
                fi ;;
        esac
        echo "incident-1105: removing $count distrusted certificates from $file"
        echo "$file" | certificates | cut -d' ' -f1 | grep -v -x -F -f "$WORK/bad" | while read -r cert; do
            printf '%s\n' -----BEGIN\ CERTIFICATE----- "$(echo "$cert" | fold -w 64)" -----END\ CERTIFICATE-----
        done > "$WORK/kept"
        cat "$WORK/kept" > "$file"
    done < "$WORK/texts"
    while IFS= read -r keystore; do
        distrusted_aliases "$keystore" > "$WORK/aliases" || continue    # step 3 reports it
        while IFS= read -r alias; do
            echo "incident-1105: deleting $alias from $keystore"
            "$KEYTOOL" -delete -alias "$alias" -keystore "$keystore" -storepass changeit < /dev/null
        done < "$WORK/aliases"
    done < "$WORK/keystores"
    # NSS's built-in roots: p11-kit-trust.so is a drop-in replacement that serves the fixed system store.
    grep '/libnssckbi\.so$' "$WORK/programs" | while IFS= read -r library; do
        for module in /usr/lib*/pkcs11/p11-kit-trust.so /usr/lib/*/pkcs11/p11-kit-trust.so; do
            if [ -f "$module" ]; then echo "incident-1105: replacing $library with a link to $module"; ln -sf "$module" "$library"; break; fi
        done
    done
}

# Step 3: search again, and fail if anything still trusts a root.
check() {
    search_image
    # Every PEM file found, and the system store as TLS libraries read it.
    for file in /etc/ssl/certs/* /etc/ssl/cert.pem /etc/pki/tls/certs/* /etc/pki/tls/cert.pem /etc/pki/ca-trust/extracted/pem/*.pem; do
        if [ -f "$file" ]; then echo "$file"; fi
    done | cat - "$WORK/texts" | certificates > "$WORK/all"
    distrusted < "$WORK/all" > "$WORK/still"
    while read -r cert file; do problem "$file trusts $(root_name "$cert")"; done < "$WORK/still"
    # A root inside JSON or source code, which step 2 cannot remove.
    while IFS= read -r file; do
        if grep -q -F -f "$WORK/starts" "$file" && ! cut -d' ' -f2- "$WORK/still" | grep -q -x -F "$file"; then
            problem "$file holds a root in a form this script cannot change (not plain PEM): fix it where it comes from"
        fi
    done < "$WORK/texts"
    if [ -n "$SYSTEM_BUNDLE" ] && ! grep -q -x -F "$USERTRUST_RSA" "$SYSTEM_BUNDLE"; then
        problem "$SYSTEM_BUNDLE lacks USERTrust RSA Certification Authority, so Sectigo sites would fail: update ca-certificates"
    fi
    while IFS= read -r keystore; do
        distrusted_aliases "$keystore" > "$WORK/aliases" || problem "no keytool can open $keystore with the password changeit"
        while IFS= read -r alias; do problem "$keystore trusts $alias"; done < "$WORK/aliases"
    done < "$WORK/keystores"
    while IFS= read -r program; do
        case $program in
            */node | */nodejs)
                case " ${NODE_OPTIONS:-} " in
                    *" --use-openssl-ca "*) "$program" -e 'process.exit(parseInt(process.versions.node) < 8 ? 1 : 0)' < /dev/null ||
                        problem "$program (Node.js) does not run, or is older than 8 and ignores NODE_OPTIONS: upgrade it" ;;
                    *) problem "$program (Node.js) has the roots built in: add ENV NODE_OPTIONS=--use-openssl-ca before the RUN line" ;;
                esac ;;
            */uv)
                if ! { [ "${UV_SYSTEM_CERTS:-}" = 1 ] && grep -q UV_SYSTEM_CERTS "$program"; } &&
                    ! { [ "${UV_NATIVE_TLS:-}" = 1 ] && grep -q UV_NATIVE_TLS "$program"; }; then
                    problem "$program (uv) has the roots built in: add ENV UV_SYSTEM_CERTS=1 (uv 0.9: UV_NATIVE_TLS=1) before the RUN line"
                fi ;;
            */libnssckbi.so)
                problem "$program (NSS's built-in roots) must be a link to p11-kit-trust.so: run this script after the last" \
                    "package install, and on Debian, Ubuntu or Alpine install p11-kit-modules or p11-kit-trust first" ;;
            *)
                problem "$program has the roots built in: upgrade it, rebuild it to use the system store, or remove it" ;;
        esac
    done < "$WORK/programs"
    files=$(cut -d' ' -f2- "$WORK/all" | sort -u | wc -l | tr -d ' ')
    echo "incident-1105: checked $files CA files; $(wc -l < "$WORK/keystores" | tr -d ' ') keystores and $(wc -l < "$WORK/programs" | tr -d ' ') programs hold a root"
    [ "$files" != 0 ] || problem "found no CA certificates to check: put this step after ca-certificates is installed"
    if [ "$PROBLEMS" != 0 ]; then
        echo "incident-1105: FAILED: see the errors above" >&2
        exit 1
    fi
    echo "incident-1105: OK: nothing in this image trusts the eMudhra roots or AAA Certificate Services"
}

if [ "$(id -u)" != 0 ]; then
    echo "incident-1105: ERROR: run this as root (put it before any USER line)" >&2
    exit 1
fi
PROBLEMS=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
echo "$ROOTS" | awk 'NF { gsub(":", "", $2); print tolower($2) }' > "$WORK/fingerprints"
echo "$ROOTS" | awk 'NF { print $3 }' > "$WORK/starts"
{ echo eMudhra; echo 'AAA Certificate Services'; cat "$WORK/starts"; } > "$WORK/patterns"
if [ -n "${INCIDENT_1105_IGNORE:-}" ]; then echo "incident-1105: leaving alone, as INCIDENT_1105_IGNORE asks: $INCIDENT_1105_IGNORE"; fi
SYSTEM_BUNDLE=
for file in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [ -f "$file" ]; then SYSTEM_BUNDLE=$file; break; fi
done
if [ "${1:-}" != --check ]; then
    fix_system_store
    search_image
    fix_copies
fi
check
