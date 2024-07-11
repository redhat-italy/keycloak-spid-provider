#!/bin/bash

# Configuration
KCADM=${1:-/opt/eap/bin/kcadm.sh}    # Location of kcadm.sh
KSERVER=${2:-http://localhost:8080}  # Server host:port
KTREALM=${3:-my-spid}                # Target Realm
CLEAN_UP=false                       # If set to true deletes every provider in the SP list

# List of Service Providers
IDP=(
"infocertid"
"namirialid"
"lepidaid"
"arubaid"
"etnaid"
"sielteid"
"infocamereid"
"intesigroupid"
"timid"
"spiditaliaid"
"posteid"
"teamsystemid"
"test/privatespid"
"test/spidtestidp"
)

# Counter for server calls
ADMIN_CALLS=0

START=$(date +%s)

# Configure keycloak
if ! ${KCADM} config credentials --server ${KSERVER} --realm master --user admin
then
    exit 1
fi
(( ADMIN_CALLS++ ))

echo "##########################################################################################"
echo "# Location of kcadm.sh: ${KCADM}"
echo "# Server is at ${KSERVER}"
echo "# Target realm is ${KTREALM}"
if [ "${CLEAN_UP}" == true ]; then
    echo "#"
    echo "# WARNING: This session will delete every Identity provider of the list. "
    echo "# Press CTRL+C now if this was a mistake!" 
    echo "#"
fi
echo "##########################################################################################"
read -n1 -r -p "Press any key to continue..." key

for idp in "${IDP[@]}";
do
    # sanitize idp alias
    idp_alias=${idp/test\//}
    if [ "${CLEAN_UP}" == true ]; then
        echo "Deleting Identity Provider with alias ${idp_alias}"
        ${KCADM} delete identity-provider/instances/${idp_alias} -r ${KTREALM}
        (( ADMIN_CALLS++ ))
        continue
    fi
    echo "Creating Identity Provider with alias ${idp_alias}"
    ${KCADM} create identity-provider/instances -r ${KTREALM} -f resources/idp/${idp}.json
    (( ADMIN_CALLS++ ))
    echo "Creating custom mappers for provider ${idp_alias}"
    for file in resources/mappers/*.json; 
    do
        dest_file="/tmp/${idp_alias}-${file##*/}"
        cat ${file} | sed "s/CHANGE-IT/${idp_alias}/" > ${dest_file}
        ${KCADM} create identity-provider/instances/${idp_alias}/mappers -r ${KTREALM} -f ${dest_file}
        (( ADMIN_CALLS++ ))
    done
done

END=$(date +%s)

echo "Done. Keycloak server received ${ADMIN_CALLS} http requests in about $((END-START)) seconds"

