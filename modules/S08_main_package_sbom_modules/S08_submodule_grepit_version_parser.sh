#!/bin/bash -p

# EMBA - SBOM from Grepit Version Extraction
# SPDX-License-Identifier: GPL-3.0-only
# Author: HackersEra Team

S08_submodule_grepit_version_parser() {
  local lOS_IDENTIFIED="${1:-}"
  local lPACKAGING_SYSTEM="grepit"

  [[ -z "${LOG_PATH}" ]] && LOG_PATH="/logs/s08_grepit_version_parser.txt"
  local lGREPIT_LOGS_DIR="${LOG_PATH%/*}/S99_grepit"
  local lWAIT_PIDS_S08_GREPIT_ARR=()
  local lPOS_RES=0

  sub_module_title "SBOM generation from Grepit version extraction" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  # Trigger Grepit if version logs not present
  if [[ ! -d "${lGREPIT_LOGS_DIR}" || -z "$(ls -A "${lGREPIT_LOGS_DIR}"/3_mil_*_version.txt 2>/dev/null)" ]]; then
    print_output "[*] Grepit version logs not found — triggering minimal Grepit (backdoor only)..." "no_log"
    export GREPIT_INCLUDE_ONLY="grepit_module_defense"
    export GREPIT_ALREADY_RUN=1
    S99_grepit
  fi

  local JSON_COMBINED="${LOG_DIR}/grepit_versions_combined.json"
  if [[ -s "${JSON_COMBINED}" ]]; then
    print_output "[*] Found Grepit combined version JSON: ${JSON_COMBINED}"
    parse_grepit_json "${JSON_COMBINED}" "${lOS_IDENTIFIED}" "${lPACKAGING_SYSTEM}"
    lPOS_RES=1
  fi

  # Legacy TXT-based grepit version parsing
  if [[ -d "${lGREPIT_LOGS_DIR}" ]]; then
    for f in "${lGREPIT_LOGS_DIR}"/3_mil_*_version.txt; do
      [[ ! -f "$f" ]] && continue
      parse_grepit_version_file_threader "${f}" "${lOS_IDENTIFIED}" "${lPACKAGING_SYSTEM}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S08_GREPIT_ARR+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_GREPIT_ARR
      lPOS_RES=1
    done
    wait_for_pid "${lWAIT_PIDS_S08_GREPIT_ARR[@]}"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    local count
    count=$(grep -c '"bom-ref":' "${SBOM_LOG_PATH}"/*.json 2>/dev/null || echo 0)
    print_output "[+] Grepit SBOM results parsed successfully." "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    print_output "[+] ${count} SBOM component(s) added from Grepit logs." "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Grepit SBOM results available"
  fi
}

parse_grepit_json() {
  local JSON_FILE="$1"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGING_SYSTEM="${3:-grepit}"

  jq -c '.[]' "${JSON_FILE}" | while read -r component; do
    local lAPP_NAME lAPP_VERS lAPP_TYPE lAPP_DESC
    local lAPP_ARCH="NA"
    local lAPP_LIC="NA"
    local lAPP_MAINT="NA"
    local lAPP_VENDOR lCPE_IDENTIFIER lPURL_IDENTIFIER
    local lSTRIPPED_VERSION lCONFIDENCE="medium"

    lAPP_NAME=$(echo "$component" | jq -r '.component')
    lAPP_VERS=$(echo "$component" | jq -r '.version')
    lAPP_DESC="Detected by Grepit: $(echo "$component" | jq -r '.detection')"
    lAPP_TYPE="application"
    lAPP_VENDOR="${lAPP_NAME}"
    lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS}"

    case "${lAPP_NAME}" in
      apache2|httpd) lAPP_VENDOR="apache" ;;
      openssl)       lAPP_VENDOR="openssl foundation" ;;
      nginx)         lAPP_VENDOR="nginx" ;;
      curl)          lAPP_VENDOR="haxx" ;;
    esac

    lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"
    lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED}" "${lPACKAGING_SYSTEM}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_ARCH}")

    local lPROP_ARRAY_INIT_ARR=(
      "source_path:${JSON_FILE}"
      "minimal_identifier:${lSTRIPPED_VERSION}"
      "confidence:${lCONFIDENCE}"
      "detection_method:grepit_version_json"
    )

    build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

    if ! build_sbom_json_hashes_arr "${JSON_FILE}" "${lAPP_NAME}" "${lAPP_VERS}" "${lPACKAGING_SYSTEM}"; then
      write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "${S08_DUPLICATES_LOG}"
      continue
    fi

    build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_MAINT}" "${lAPP_LIC}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"

    write_log "[*] Grepit JSON detection: ${lAPP_NAME} - ${lAPP_VERS}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_csv_log "${lPACKAGING_SYSTEM}" "${JSON_FILE}" "NA/NA/NA" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
  done
}

parse_grepit_version_file_threader() {
  local lVERSION_FILE="${1}"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGING_SYSTEM="${3:-grepit}"
  local lLINE=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lCPE_IDENTIFIER=""
  local lPURL_IDENTIFIER=""
  local lAPP_TYPE="application"
  local lAPP_DESC="Detected by Grepit keyword scan"
  local lAPP_ARCH="NA"
  local lAPP_LIC="NA"
  local lAPP_MAINT="NA"
  local lAPP_VENDOR="NA"
  local lSTRIPPED_VERSION=""
  local lPROP_ARRAY_INIT_ARR=()
  local lCONFIDENCE="medium"

  [[ "${lVERSION_FILE}" =~ _high_ ]] && lCONFIDENCE="high"

  while read -r lLINE; do
    [[ -z "$lLINE" ]] && continue

    if [[ "$lLINE" =~ ([a-zA-Z0-9_\.\-]+)[[:space:]_vV-]*([0-9]+(\.[0-9]+){1,3}([a-zA-Z0-9\-\.]*)?) ]]; then
      lAPP_NAME="${BASH_REMATCH[1]}"
      lAPP_VERS="${BASH_REMATCH[2]}"
    else
      continue
    fi

    lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
    lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
    lAPP_VENDOR="${lAPP_NAME}"
    lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS}"

    case "${lAPP_NAME}" in
      apache2|httpd) lAPP_VENDOR="apache" ;;
      openssl)       lAPP_VENDOR="openssl foundation" ;;
      nginx)         lAPP_VENDOR="nginx" ;;
      curl)          lAPP_VENDOR="haxx" ;;
    esac

    lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"
    lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED}" "${lPACKAGING_SYSTEM}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_ARCH}")

    lPROP_ARRAY_INIT_ARR=(
      "source_path:${lVERSION_FILE}"
      "minimal_identifier:${lSTRIPPED_VERSION}"
      "confidence:${lCONFIDENCE}"
      "detection_method:grepit_version_string"
    )

    build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

    if ! build_sbom_json_hashes_arr "${lVERSION_FILE}" "${lAPP_NAME}" "${lAPP_VERS}" "${lPACKAGING_SYSTEM}"; then
      write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "${S08_DUPLICATES_LOG}"
      continue
    fi

    build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_MAINT}" "${lAPP_LIC}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"

    write_log "[*] Grepit detection: ${lAPP_NAME} - ${lAPP_VERS}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_csv_log "${lPACKAGING_SYSTEM}" "${lVERSION_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
  done < "${lVERSION_FILE}"
}
