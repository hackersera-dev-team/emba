#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# The original code (from line 187 till the end of the file) from the CRASS project is licensed the following way:
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# July 2013
# ----------------------------------------------------------------------------
#
# Original Author: Floyd - https://github.com/floyd-fuh
# EMBA Author(s): Michael Messner, Pascal Eckmann

# Description:  Initial implementation of the great grepit tool from CRASS (code review audit script scanner)
#               CRASS: https://github.com/floyd-fuh/crass/
#               Grepit: https://github.com/floyd-fuh/crass/blob/master/grep-it.sh
#               Original grepit description:
#               A simple greper for code, loot, IT-tech-stuff-the-customer-throws-at-you.
#               Tries to find IT security and privacy related stuff.

# shellcheck disable=SC2016

S99_grepit() {

  module_log_init "${FUNCNAME[0]}"

  if [[ "${QUICK_SCAN:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Intelligent grepit module"
  print_output "Running intelligent grepit module for identification of interesting spots within the firmware ..." "no_log"

  pre_module_reporter "${FUNCNAME[0]}"

  local lWAIT_PIDS_S99_ARR=()
  local lGREPIT_MODULES_ARR=()
  local lGREPIT_RESULTS=0

  local lMAX_MOD_THREADS=1
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"/3 ))


  # grepit options:
  # Sometimes we look for composite words with wildcard, eg. root.{0,20}detection, this is the maximum
  # of random characters that can be in between. The higher the value the more strings will potentially be flagged.
  export WILDCARD_SHORT=20
  export WILDCARD_LONG=200
  # Weird grep behaviour with clearing to the end of line -.-
  # This variable prevents this behaviour
  export GREP_COLORS=ne
  # sometimes we have so many results. We need to limit it a bit
  # -m is limit per file and in this case per grep search per file
  local lLIMIT_GREP=(-m 100)
  # Do not remove -rP if you don't know what you are doing, otherwise you probably break this script
  local lGREP_ARGUMENTS=(-a -n -A 1 -B 3 -rP)
  # Open the colored outputs with "less -R" or cat, otherwise remove --color=always (not recommended, colors help to find the matches in huge text files)
  local lCOLOR_ARGUMENTS=("--color=always")
  export STANDARD_GREP_ARGUMENTS=("${lGREP_ARGUMENTS[@]}" "${lCOLOR_ARGUMENTS[@]}" "${lLIMIT_GREP[@]}")
  export ENABLE_LEAST_LIKELY=0

  mapfile -t lGREPIT_MODULES_ARR < <(grep -E "^grepit_module.*\(\) " "${MOD_DIR}"/"${FUNCNAME[0]}".sh | sed -e 's/()\ .*//g' | sort -u)
  print_output "[*] Loaded ${ORANGE}${#lGREPIT_MODULES_ARR[@]}${NC} grepit modules\n"

  write_csv_log "Grepit test" "Number of results" "Used args for grep" "Regex used" "Grepit comment"

  if [[ ${THREADED} -eq 1 ]]; then
    for GREPIT_MODULE in "${lGREPIT_MODULES_ARR[@]}"; do
      "${GREPIT_MODULE}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S99_ARR+=( "${lTMP_PID}" )
      store_kill_pids "${lTMP_PID}"
      max_pids_protection "${lMAX_MOD_THREADS}" lWAIT_PIDS_S99_ARR
    done
  else
    for GREPIT_MODULE in "${lGREPIT_MODULES_ARR[@]}"; do
      "${GREPIT_MODULE}"
    done
  fi

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S99_ARR[@]}"

  grepit_reporter

  lGREPIT_RESULTS=$(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}"/[0-9]_* | cut -d: -f2 | paste -sd+ | bc || true)
  print_output "\n"
  print_output "[*] Found ${ORANGE}${lGREPIT_RESULTS}${NC} results via grepit."

  module_end_log "${FUNCNAME[0]}" "${lGREPIT_RESULTS}"
}

grepit_reporter() {
  local lCSV_LOG=""
  lCSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  lCSV_LOG="${CSV_DIR}""/""${lCSV_LOG}"
  local lGREPIT_RESULTS_DETAILS_ARR=()
  local lRESULT=""
  local lCURRENT_TEST=""
  local lLINES_OF_OUTPUT=""
  local lCOMMENT=""
  local lOUTFILE=""

  if [[ -f "${lCSV_LOG}" ]]; then
    readarray -t lGREPIT_RESULTS_DETAILS_ARR < <(cut -d\; -f1,2,5 "${lCSV_LOG}" | grep -v "Grepit test" | grep -v "^$" | sort -u)
    for lRESULT in "${lGREPIT_RESULTS_DETAILS_ARR[@]}"; do
      lCURRENT_TEST=$(echo "${lRESULT}" | cut -d\; -f1)
      lLINES_OF_OUTPUT=$(echo "${lRESULT}" | cut -d\; -f2)
      lCOMMENT=$(echo "${lRESULT}" | cut -d\; -f3)
      lOUTFILE="${lCURRENT_TEST}".txt

      print_output "[*] ${ORANGE}${lLINES_OF_OUTPUT}${NC} results of grepit module ${ORANGE}${lCURRENT_TEST}${NC} (${ORANGE}${lCOMMENT}${NC})." "" "${LOG_PATH_MODULE}/${lOUTFILE}"
    done
  fi
}

grepit_search() {
  local lLINES_OF_OUTPUT=0
  local lGREP_COMMAND="grep"
  local lLOG_DETAILS=1
  local lCOMMENT="${1:-NA}"
  local lEXAMPLE="${2:-NA}"
  local lFALSE_POSITIVES_EXAMPLE="${3:-NA}"
  local lSEARCH_REGEX="${4}"
  local lOUTFILE="${5:-MISSING_LOG_DIR.txt}"
  local lCURRENT_TEST=""
  if [[ -v 6 ]]; then
    local lARGS_FOR_GREP_ARR=("${6}") # usually just -i for case insensitive or empty, very rare we use -o for match-only part with no context info
  else
    local lARGS_FOR_GREP_ARR=()
  fi

  if [[ "${ENABLE_LEAST_LIKELY}" -eq 0 ]] && [[ "${lOUTFILE}" == 9_* ]]; then
    print_output "[-] Skipping searching for ${lOUTFILE} with regex ${lSEARCH_REGEX}. Set ENABLE_LEAST_LIKELY in the module options to 1 if you would like to." "no_log"
  else
    write_log "[*] Searching (args for grep: ${ORANGE}${lARGS_FOR_GREP_ARR[*]}${NC}) for ${ORANGE}${lSEARCH_REGEX}${NC}." "${LOG_PATH_MODULE}/${lOUTFILE}"

    if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
      write_log "[*] Grepit state info - comment: ${ORANGE}${lCOMMENT}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Filename ${ORANGE}${lOUTFILE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Example: ${ORANGE}${lEXAMPLE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - False positive example: ${ORANGE}${lFALSE_POSITIVES_EXAMPLE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Grep args: ${ORANGE}${lARGS_FOR_GREP_ARR[*]}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Search regex: ${ORANGE}${lSEARCH_REGEX}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "" "${LOG_PATH_MODULE}/${lOUTFILE}"
    fi

    ulimit -Sv "${lMEM_LIMIT}"
    "${lGREP_COMMAND}" "${lARGS_FOR_GREP_ARR[@]}" "${STANDARD_GREP_ARGUMENTS[@]}" -- "${lSEARCH_REGEX}" "${FIRMWARE_PATH}" |& safe_logging "${LOG_PATH_MODULE}/${lOUTFILE}" 0 || true
    ulimit -Sv unlimited

    if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
      if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]] && ! [[ $(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null) -gt 7 ]]; then
        rm "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null
      fi
    else
      if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]] && ! [[ $(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null) -gt 0 ]]; then
        rm "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null
      fi
    fi
    if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]]; then
      if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
        lLINES_OF_OUTPUT=$(( "$(wc -l < "${LOG_PATH_MODULE}/${lOUTFILE}")" -8 ))
      else
        lLINES_OF_OUTPUT=$(( "$(wc -l < "${LOG_PATH_MODULE}/${lOUTFILE}")" -1 ))
      fi
      lCURRENT_TEST=$(basename -s .txt "${lOUTFILE}")
      # this is the output to the terminal. For the final report we wait till all tests are finished and then we
      # parse the csv output file and sort it according the test priority - 1-9, where 1 is more interesting
      # (low false positive rate, certainty of "vulnerability") and 9 is only "you might want to have a look when you are desperately looking for vulns")
      print_output "[*] ${ORANGE}${lLINES_OF_OUTPUT}${NC} results of grepit module ${ORANGE}${lCURRENT_TEST}${NC}." "no_log"
      write_csv_log "${lCURRENT_TEST}" "${lLINES_OF_OUTPUT}" "${lARGS_FOR_GREP_ARR[*]}" "${lSEARCH_REGEX}" "${lCOMMENT}"
    fi
  fi
}

grepit_version_extract() {
  local NAME="$1"
  local REGEX="$2"
  local OUTFILE="$3"
  local DETECTION="$4"
  local SAMPLE="$5"

  local VERSION_JSON_TEMP="${LOG_DIR}/grepit_versions_combined.json.tmp"
  local CUSTOM_LIST="${TOOL_PATH}/external/component_list/custom_component_list_defense.txt"
  local NVD_LIST="${TOOL_PATH}/external/component_list/nvd_product_list.txt"

  grepit_search \
    "${NAME} version pattern" \
    "${SAMPLE}" \
    "binary strings, ELF symbols or banner" \
    "${REGEX}" \
    "${OUTFILE}" \
    "-i"

  local OUTFILE_PATH="${LOG_PATH_MODULE}/${OUTFILE}"
  local MATCHES
  MATCHES=$(grep -aPo "${REGEX}" "${OUTFILE_PATH}" 2>/dev/null | sort -u)

  if [[ -n "${MATCHES}" ]]; then
    while IFS= read -r VER; do
      [[ -z "$VER" ]] && continue
      local DEDUP_KEY="${NAME}::${VER}"
      if grep -q "\"${NAME}\".*\"${VER}\"" "${VERSION_JSON_TEMP}" 2>/dev/null; then
        continue
      fi

      local vendor="Unknown"
      local license="Unknown"
      local entry=""

      # Custom list check
      if [[ -f "$CUSTOM_LIST" ]]; then
        entry=$(grep -i -E "^${NAME}[[:space:]]*\|" "$CUSTOM_LIST" | head -n1)
        if [[ -n "$entry" ]]; then
          vendor=$(echo "$entry" | cut -d'|' -f2 | xargs)
          license=$(echo "$entry" | cut -d'|' -f3 | xargs)
        fi
      fi

      # NVD list fallback
      if [[ "$vendor" == "Unknown" && -f "$NVD_LIST" ]]; then
        entry=$(grep -i -E "^${NAME}[[:space:]]*\|" "$NVD_LIST" | head -n1)
        if [[ -n "$entry" ]]; then
          vendor=$(echo "$entry" | cut -d'|' -f2 | xargs)
        fi
      fi

      jq -n \
        --arg name "${NAME}" \
        --arg version "${VER}" \
        --arg vendor "${vendor}" \
        --arg license "${license}" \
        --arg detection "${DETECTION}" \
        '{component: $name, version: $version, vendor: $vendor, license: $license, detection: $detection}' \
        >> "${VERSION_JSON_TEMP}"
    done <<< "${MATCHES}"
  fi
}

grepit_module_defense() {
  print_output "[*] Starting Grepit Defense module"

  : "${TOOL_PATH:=/home/vikash/tools/emba}"

  local LOG_DIR="${LOG_DIR:-/tmp/emba_logs}"      # Set default if not defined
  local LOG_PATH_MODULE="${LOG_PATH_MODULE:-${LOG_DIR}}"  # Use LOG_DIR as fallback
  local CUSTOM_LIST="${TOOL_PATH}/external/component_list/custom_component_list_defense.txt"
  local NVD_LIST="${TOOL_PATH}/external/component_list/nvd_product_list.txt"

  local VERSION_JSON_OUT="${LOG_DIR}/grepit_versions_combined.json"
  local VERSION_JSON_TEMP="${VERSION_JSON_OUT}.tmp"
  : > "${VERSION_JSON_TEMP}"  # Clear temp JSON buffer

  # === Backdoor Detection (unchanged) ===
  grepit_search \
    "Drone/MIL backdoor trigger keywords" \
    '[Backdoor Triggered] UID:' \
    'debug log with UID shown' \
    "fieldop|milops#2025|/etc/init.d/.remote_init|remote shell|nc[\s-]+l[\s-]+p[\s0-9]+[\s-]+e[\s-]+/bin/sh|reboot -f|back.{0,8}door|Actuating flaps|EMERGENCY OVERRIDE" \
    "3_mil_backdoor.txt" \
    "-i"

  # === Static Component Pattern Table ===
  declare -A COMPONENT_PATTERNS=(
    [busybox]='(?i)busybox[ _-]?v?([0-9]+\.[0-9]+\.[0-9]+)'
    [openssl]='(?i)openssl[ _-]?([0-9]+\.[0-9]+\.[0-9]+[a-z]?)'
    [libssl]='libssl\.so\.([0-9]+\.[0-9]+\.[0-9][a-z]?)'
    [uclibc]='(?i)uclibc[ _-]?v?([0-9]+\.[0-9]+\.[0-9]+)'
    [dropbear]='(?i)dropbear[ _-]?v?([0-9]{4}\.[0-9]+)'
    [glibc]='GLIBC_([0-9]+\.[0-9]+)'
    [libc]='(?i)libc[ _-]?v?([0-9]+\.[0-9]+)'
    [libm]='(?i)libm[ _-]?([0-9]+\.[0-9]+)'
    [libpthread]='(?i)libpthread[ _-]?([0-9]+\.[0-9]+)'
    [libz]='(?i)libz[ _-]?([0-9]+\.[0-9]+)'
    [libcrypto]='(?i)libcrypto[ _-]?([0-9]+\.[0-9]+\.[0-9]+[a-z]?)'
    [libcurl]='(?i)libcurl[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libexpat]='(?i)libexpat[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libpng]='(?i)libpng[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libjpeg]='(?i)libjpeg[ _-]?([0-9]+[a-z]?)'
    [libwebp]='(?i)libwebp[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libtiff]='(?i)libtiff[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libsqlite3]='(?i)libsqlite3[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libxml2]='(?i)libxml2[ _-]?([0-9]+\.[0-9]+\.[0-9]+)'
    [libffi]='(?i)libffi[ _-]?([0-9]+\.[0-9]+)'
  )

  for component in "${!COMPONENT_PATTERNS[@]}"; do
    local regex="${COMPONENT_PATTERNS[$component]}"
    local outfile="3_mil_${component}_version.txt"
    grepit_version_extract "${component}" "${regex}" "${outfile}" "grepit" "${component}"
  done

  # === Dynamic Scan: custom_component_list_defense.txt ===
  if [[ -f "$CUSTOM_LIST" ]]; then
    while IFS='|' read -r name _ _; do
      name=$(echo "$name" | xargs)
      [[ -z "$name" || "$name" =~ ^# ]] && continue
      local regex="(?i)${name}[ /:_-]*v?([0-9]+\.[0-9]+(\.[0-9a-zA-Z]+)?)"
      local outfile="3_mil_dyn_custom_${name}_version.txt"
      grepit_version_extract "$name" "$regex" "$outfile" "grepit_list" "$name"
    done < "$CUSTOM_LIST"
  fi

  # === Dynamic Scan: nvd_product_list.txt ===
  if [[ -f "$NVD_LIST" ]]; then
    while IFS='|' read -r name _; do
      name=$(echo "$name" | xargs)
      [[ -z "$name" || "$name" =~ ^# ]] && continue
      local regex="(?i)${name}[ /:_-]*v?([0-9]+\.[0-9]+(\.[0-9a-zA-Z]+)?)"
      local outfile="3_mil_dyn_nvd_${name}_version.txt"
      grepit_version_extract "$name" "$regex" "$outfile" "grepit_nvd" "$name"
    done < "$NVD_LIST"
  fi

  # === Embedded SBOM JSON Parsing ===
  local EMBEDDED_JSON_FILE="3_mil_embedded_sbom.json"
  local EMBEDDED_REGEX='"name"\s*:\s*"([^"]+)"\s*,\s*"version"\s*:\s*"([^"]+)"'

  grepit_search \
    "Embedded SBOM JSON components" \
    '"name": "busybox", "version": "1.35.0"' \
    'JSON section in firmware' \
    "${EMBEDDED_REGEX}" \
    "${EMBEDDED_JSON_FILE}" \
    "-i"

  if [[ -f "${LOG_PATH_MODULE}/${EMBEDDED_JSON_FILE}" ]]; then
    grep -aPo "${EMBEDDED_REGEX}" "${LOG_PATH_MODULE}/${EMBEDDED_JSON_FILE}" | while read -r line; do
      local name version
      name=$(echo "$line" | grep -oP '"name"\s*:\s*"\K[^"]+')
      version=$(echo "$line" | grep -oP '"version"\s*:\s*"\K[^"]+')
      [[ -n "$name" && -n "$version" ]] || continue
      grep -q "\"${name}\".*\"${version}\"" "${VERSION_JSON_TEMP}" 2>/dev/null && continue
      jq -n \
        --arg name "$name" \
        --arg version "$version" \
        --arg detection "embedded_sbom_json" \
        '{component: $name, version: $version, vendor: "Unknown", license: "Unknown", detection: $detection}' \
        >> "${VERSION_JSON_TEMP}"
    done
  fi

  # === Finalize Output ===
  if [[ -s "${VERSION_JSON_TEMP}" ]]; then
    jq -s '.' "${VERSION_JSON_TEMP}" > "${VERSION_JSON_OUT}" && rm -f "${VERSION_JSON_TEMP}"
    print_output "[+] Combined Grepit SBOM JSON saved to: ${VERSION_JSON_OUT}"
  else
    rm -f "${VERSION_JSON_TEMP}" "${VERSION_JSON_OUT}"
  fi
}

