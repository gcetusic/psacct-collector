#!/bin/sh

KINIT=/usr/sue/bin/kinit
KDESTROY=/usr/kerberos/bin/kdestroy

$KINIT -k

export KRB5CCNAME


# Set environment
# Priorities:
#   1. first script argument
#   2. GRATIA environment variable
#   3. default _gratia_dir variable

_gratia_dir=/opt/psacct-collector

if [ -n "${GRATIA}" ] ; then
    _gratia_dir=$GRATIA
fi

if [ ! "$1" == '' ] ; then
    _gratia_dir=$1
fi

_gratia_data_dir="/var/psacct-collector/data"

if [ ! -f ${_gratia_data_dir} ] ; then
    mkdir -p ${_gratia_data_dir}
fi

# Now run gratia
if [ -d ${_gratia_dir} ] ; then
    cd "${_gratia_dir}"
    if test -n "$PYTHONPATH" ; then
        if echo "$PYTHONPATH" | grep -e ':$' >/dev/null 2>&1; then
            PYTHONPATH="${PYTHONPATH}${_gratia_dir}:"
        else
            PYTHONPATH="${PYTHONPATH}:${_gratia_dir}"
        fi
    else
        PYTHONPATH="${_gratia_dir}"
    fi
else
    echo "There is no Gratia probe installation present: pssact-collector folder missing"
fi

export PYTHONPATH
python "${_gratia_dir}/PSACCTProbe.py"

$KDESTROY

