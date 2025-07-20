#!/bin/bash -p

# EMBA - Minimal Disclosure Parser (JSON Output Only)
# SPDX-License-Identifier: GPL-3.0-only
# Author: HackersEra Team

S08_submodule_grepit_information_disclosure_parser() {
  local JSON_FILE="${LOG_PATH_MODULE}/grepit_info_disclosure.json"
  local OUT_JSON="${LOG_PATH_MODULE}/grepit_info_disclosure_summary.json"
  local TMP_JSON="${OUT_JSON}.tmp"

  mkdir -p "$(dirname "${OUT_JSON}")"
  : > "${TMP_JSON}"

  if [[ ! -f "${JSON_FILE}" ]]; then
    print_output "[*] Grepit info disclosure not found — running disclosure scan..." "no_log"
    export GREPIT_INCLUDE_ONLY="grepit_module_information_disclosure"
    export GREPIT_ALREADY_RUN=1
    S99_grepit
  fi

  if [[ -s "${JSON_FILE}" ]]; then
    local count=0
    jq -c '.[]' "${JSON_FILE}" | while read -r entry; do
      local type match description file_path evidence confidence="medium"
      type=$(echo "$entry" | jq -r '.type')
      match=$(echo "$entry" | jq -r '.match')
      description=$(echo "$entry" | jq -r '.description')
      file_path=$(echo "$entry" | jq -r '.file_path // empty')
      evidence=$(echo "$entry" | jq -r '.evidence // empty')

      # Escalate confidence if critical terms are detected
      if echo "$match" | tr '[:upper:]' '[:lower:]' | grep -qE 'kill[_\- ]?switch|uplink|reverse[_\-]?shell|geo[_\- ]?fence|fail[_\- ]?safe'; then
        confidence="high"
      fi

      jq -n \
        --arg type "$type" \
        --arg match "$match" \
        --arg description "$description" \
        --arg file_path "$file_path" \
        --arg evidence "$evidence" \
        --arg confidence "$confidence" \
        '{type: $type, match: $match, description: $description, file_path: $file_path, evidence: $evidence, confidence: $confidence}' \
        >> "${TMP_JSON}"
      echo "" >> "${TMP_JSON}"
      ((count++))
    done

    jq -s '.' "${TMP_JSON}" > "${OUT_JSON}" && rm -f "${TMP_JSON}"
    print_output "[+] Grepit disclosure summary JSON saved to: ${OUT_JSON}"
    print_output "[+] ${count} disclosure finding(s) written to summary."
  else
    print_output "[*] No disclosure results available for parsing."
  fi
}
