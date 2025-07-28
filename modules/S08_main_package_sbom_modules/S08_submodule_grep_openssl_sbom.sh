#!/bin/bash -p

S08_submodule_grep_openssl_sbom() {
  local lPACKAGING_SYSTEM="grep_openssl_sbom"
  local lOS_IDENTIFIED="${1:-}"
  local lPOS_RES=0
  local lSBOM_COMPONENT_FILES_ARR=()
  local lSBOM_FILE=""
  local lWAIT_PIDS_S08_OPENSLL_ARR=()

  sub_module_title "SBOM OpenSSL version scanner" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  # Fallback: If SBOM_LOG_PATH not set, use LOG_PATH/SBOM
  if [[ -z "${SBOM_LOG_PATH}" || ! -d "${SBOM_LOG_PATH}" ]]; then
    SBOM_LOG_PATH="${LOG_PATH}/SBOM"
  fi

  write_log "[DEBUG] Using SBOM_LOG_PATH=${SBOM_LOG_PATH}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  # Collect SBOM component JSON files
  mapfile -t lSBOM_COMPONENT_FILES_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "*.json" 2>/dev/null)

  if [[ "${#lSBOM_COMPONENT_FILES_ARR[@]}" -eq 0 ]]; then
    write_log "[-] No SBOM component files found! SBOM_LOG_PATH=${SBOM_LOG_PATH}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  for lSBOM_FILE in "${lSBOM_COMPONENT_FILES_ARR[@]}"; do
    grep_openssl_sbom_worker "${lSBOM_FILE}" "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S08_OPENSLL_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_OPENSLL_ARR
    lPOS_RES=1
  done

  wait_for_pid "${lWAIT_PIDS_S08_OPENSLL_ARR[@]}"

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] OpenSSL SBOM grep results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No OpenSSL SBOM results available"
  fi
}
