#!/bin/bash
#
# Given an input file containing a base-64, DER encoded, ASN.1
# SubjectPublicKeyInfo ECC public key, outputs the DPP "chirp" hash. The chirp
# hash is the SHA256 hash of the ASCII text "chirp" concatenated with the base64
# encoding of the key.

FILE=
DPP_EK_PUB=
DPP_VERSION=
VERBOSE=0

while getopts "vf:12" opt; do
    case ${opt} in
        f)
            FILE="${OPTARG}"
            ;;
        1)
            DPP_VERSION=1
            ;;
        2)
            DPP_VERSION=2
            ;;
        v)
            VERBOSE=1
            ;;
    esac
done

# if file not specified, use first arg, otherwise stdin
if [ -z "${FILE}" ]; then
    while read line
    do
        DPP_EK_PUB+=${line}
    done < "${1:-/dev/stdin}"
# otherwise ensure file exists and is regular
elif [ ! -f "${FILE}" ]; then
    echo "error: base64 file ${FILE} does not exist"
    exit 1
else
    DPP_EK_PUB=$(<${FILE})
fi

echo -e "\e[0;38;5;217m> key info\e[0m"

# ASN.1 SubjectPublicKeyInfo
echo -ne "\e[0;94m         dpp uri \e[0m-> "
echo "DPP:V:${DPP_VERSION:=2};K:${DPP_EK_PUB};;"
echo -e "\e[0;94m      base64-der \e[0m-> ${DPP_EK_PUB}"

# Public key sha256 hash
echo -ne "\e[0;94m    sha256|plain \e[0m-> "
echo -n "${DPP_EK_PUB}" | base64 -d | sha256sum -b | head -c 64
echo

# Public key sha256 hash (chirp)
echo -ne "\e[0;94m    sha256|chirp \e[0m-> "
{ echo -n "chirp" ; echo ${DPP_EK_PUB} | base64 -d ; } | sha256sum -b | head -c 64
echo

# ASN.1 details
if [ "${VERBOSE}" -ne 0 ]; then
    echo -e "\n\e[0;38;5;217m> asn.1 decoding\e[0m"
    echo "${DPP_EK_PUB}" | openssl asn1parse -dump
fi
