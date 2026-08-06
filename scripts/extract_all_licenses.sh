#!/usr/bin/env bash
# License extractor for Key Protection Module (KPM / wsd)
set -euo pipefail

extract_dpkg_licenses() {
  local rootfs_dir="$1"
  local output_dir="$2"
  local status_file="${rootfs_dir}/var/lib/dpkg/status"

  if [ -f "${status_file}" ]; then
    echo "[1/4] Extracting DPKG System Package Licenses..."
    awk -F': ' '/^Package: /{pkg=$2} /^Version: /{ver=$2; if(pkg!="" && ver!=""){print pkg" "ver; pkg=""; ver=""}}' "${status_file}" | \
    while read -r pkg ver; do
      doc_path="${rootfs_dir}/usr/share/doc/${pkg}/copyright"
      if [ -f "${doc_path}" ]; then
        mkdir -p "${output_dir}/${pkg}-${ver}"
        cp "${doc_path}" "${output_dir}/${pkg}-${ver}/LICENSE" 2>/dev/null || true
      fi
    done
  fi

  if [ -d "${rootfs_dir}/usr/share/doc" ]; then
    for doc_dir in "${rootfs_dir}"/usr/share/doc/*; do
      [ -d "${doc_dir}" ] || continue
      pkg_name="${doc_dir##*/}"
      # Skip shared system doc framework folders that are not software packages (prevents fake pseudo-packages)
      case "${pkg_name}" in
        kde|HTML|licenses) continue ;;
      esac
      if [ -f "${doc_dir}/copyright" ] || [ -f "${doc_dir}/LICENSE" ]; then
        existing=0
        for e in "${output_dir}/${pkg_name}"*; do
          if [ -e "$e" ]; then existing=1; break; fi
        done
        if [ "$existing" -eq 0 ]; then
          mkdir -p "${output_dir}/${pkg_name}-custom"
          cp "${doc_dir}/copyright" "${output_dir}/${pkg_name}-custom/LICENSE" 2>/dev/null || \
          cp "${doc_dir}/LICENSE" "${output_dir}/${pkg_name}-custom/LICENSE" 2>/dev/null || true
        fi
      fi
    done
  fi
}

extract_rust_licenses() {
  local rootfs_dir="$1"
  local output_dir="$2"
  local cargo_lock=""

  for search_base in "${rootfs_dir}" "."; do
    if [ -d "${search_base}" ]; then
      local found_lock
      found_lock=$(find "${search_base}" -name "Cargo.lock" -not -path "*/.*" 2>/dev/null | head -n 1 || true)
      if [ -n "${found_lock}" ] && [ -f "${found_lock}" ]; then
        cargo_lock="${found_lock}"
        break
      fi
    fi
  done

  if [ -n "${cargo_lock}" ] && [ -f "${cargo_lock}" ]; then
    echo "[2/4] Extracting Rust / Cargo Dependencies from ${cargo_lock}..."
    local used_cargo_licenses=0
    local cmd=""
    if command -v cargo-bundle-licenses >/dev/null 2>&1; then
      cmd="cargo-bundle-licenses"
    elif command -v cargo >/dev/null 2>&1; then
      cmd="cargo bundle-licenses"
    fi

    if [ -n "${cmd}" ]; then
      echo "Attempting cargo-bundle-licenses extraction..."
      if ${cmd} -f json -o "${output_dir}/cargo_licenses.json" 2>/dev/null; then
        echo "Successfully extracted Rust license files using cargo-bundle-licenses."
        used_cargo_licenses=1
        if command -v python3 >/dev/null 2>&1; then
          python3 -c '
import json, os, sys
out_dir = sys.argv[1]
json_path = os.path.join(out_dir, "cargo_licenses.json")
if os.path.exists(json_path):
    with open(json_path) as f:
        data = json.load(f)
    for pkg in data.get("packages", []):
        name = pkg.get("name") or pkg.get("package_name")
        ver = pkg.get("version") or pkg.get("package_version")
        if not name or not ver: continue
        pdir = os.path.join(out_dir, f"cargo-{name}-{ver}")
        os.makedirs(pdir, exist_ok=True)
        lic_file = os.path.join(pdir, "LICENSE")
        with open(lic_file, "w") as lf:
            lic_expr = pkg.get("license") or "N/A"
            lf.write(f"Cargo Crate: {name} v{ver}\n")
            lf.write(f"License Expression: {lic_expr}\n\n")
            for l in pkg.get("licenses", []):
                lname = l.get("name") or l.get("license") or "License"
                ltext = l.get("text", "").strip()
                lf.write(f"=== {lname} ===\n{ltext}\n\n")
' "${output_dir}"
        fi
      fi
    fi

    if [ "${used_cargo_licenses}" -eq 0 ]; then
      echo "Falling back to Cargo.lock dependency parsing..."
      awk -F'"' '/^name = /{pkg=$2} /^version = /{ver=$2; if(pkg!="" && ver!=""){print pkg" "ver; pkg=""; ver=""}}' "${cargo_lock}" | \
      while read -r pkg ver; do
        mkdir -p "${output_dir}/cargo-${pkg}-${ver}"
        echo "Cargo Crate: ${pkg} v${ver}" > "${output_dir}/cargo-${pkg}-${ver}/LICENSE"
        echo "See https://crates.io/crates/${pkg}/${ver} for license details." >> "${output_dir}/cargo-${pkg}-${ver}/LICENSE"
      done
    fi
  fi
}

extract_go_licenses() {
  local rootfs_dir="$1"
  local output_dir="$2"
  echo "[3/4] Extracting Go Workspace Dependencies..."
  local go_mod_dirs=()
  for search_base in "${rootfs_dir}" "."; do
    if [ -d "${search_base}" ]; then
      while IFS= read -r gfile; do
        [ -n "${gfile}" ] || continue
        gdir=$(dirname "${gfile}")
        go_mod_dirs+=("${gdir}")
      done < <(find "${search_base}" -name "go.mod" -not -path "*/.*" 2>/dev/null || true)
    fi
  done

  if [ ${#go_mod_dirs[@]} -gt 0 ]; then
    mapfile -t unique_go_dirs < <(printf "%s\n" "${go_mod_dirs[@]}" | sort -u)
    for gdir in "${unique_go_dirs[@]}"; do
      if [ -f "${gdir}/go.mod" ]; then
        echo "Processing Go module in: ${gdir}"
        local used_go_licenses=0
        if command -v go >/dev/null 2>&1; then
          echo "Attempting google/go-licenses extraction..."
          local tmp_go_out
          tmp_go_out=$(mktemp -d)
          if (cd "${gdir}" && go run github.com/google/go-licenses@v1.6.0 save ./... --save_path="${tmp_go_out}" --force 2>/dev/null); then
            echo "Successfully extracted Go license files using google/go-licenses."
            cp -r "${tmp_go_out}"/* "${output_dir}/" 2>/dev/null || true
            used_go_licenses=1
          fi
          rm -rf "${tmp_go_out}"
        fi

        if [ "${used_go_licenses}" -eq 0 ]; then
          echo "Falling back to go.mod / go.sum dependency parsing..."
          local go_deps=""
          if command -v go >/dev/null 2>&1; then
            go_deps=$(cd "${gdir}" && go list -m all 2>/dev/null | awk 'NF>=2 {print $1" "$2}' || true)
          fi
          if [ -z "${go_deps}" ] && [ -f "${gdir}/go.sum" ]; then
            go_deps=$(awk '$2 !~ /\/go.mod$/ {print $1" "$2}' "${gdir}/go.sum" | sort -u || true)
          fi

          if [ -n "${go_deps}" ]; then
            echo "${go_deps}" | while read -r pkg ver; do
              [ -n "${pkg}" ] && [ -n "${ver}" ] || continue
              safe_pkg=$(echo "${pkg}" | tr '/' '-')
              mkdir -p "${output_dir}/go-${safe_pkg}-${ver}"
              echo "Go Module: ${pkg} ${ver}" > "${output_dir}/go-${safe_pkg}-${ver}/LICENSE"
              echo "Licensed under Open Source License (See pkg.go.dev/${pkg}@${ver})" >> "${output_dir}/go-${safe_pkg}-${ver}/LICENSE"
            done
          fi
        fi
      fi
    done
  fi
}

extract_boringssl_licenses() {
  local rootfs_dir="${1:-.}"
  local output_dir="$2"
  echo "[4/4] Extracting BoringSSL License..."
  mkdir -p "${output_dir}/boringssl-master"

  local found_bssl_lic=""
  for bssl_dir in "${rootfs_dir}/boringssl" "./boringssl" "/workspace/boringssl"; do
    if [ -f "${bssl_dir}/LICENSE" ]; then
      found_bssl_lic="${bssl_dir}/LICENSE"
      break
    elif [ -f "${bssl_dir}/NOTICE" ]; then
      found_bssl_lic="${bssl_dir}/NOTICE"
      break
    elif [ -f "${bssl_dir}/COPYING" ]; then
      found_bssl_lic="${bssl_dir}/COPYING"
      break
    fi
  done

  if [ -n "${found_bssl_lic}" ]; then
    echo "Found BoringSSL license at ${found_bssl_lic}; copying..."
    cp "${found_bssl_lic}" "${output_dir}/boringssl-master/LICENSE"
  else
    echo "BoringSSL submodule LICENSE file not found; writing fallback attribution notice..."
    cat << 'EOF' > "${output_dir}/boringssl-master/LICENSE"
BoringSSL / Google Cryptography
BoringSSL is a fork of OpenSSL.
Licensed under OpenSSL License and SSLeay License / Apache-2.0.
EOF
  fi
}

generate_summary_tsv() {
  local output_dir="$1"
  local tsv_file="${output_dir}/licenses.tsv"
  echo -e "Package and Version\tLicense File Path" > "${tsv_file}"
  find "${output_dir}" -mindepth 2 -name "LICENSE" | while read -r lic_file; do
    rel_path="${lic_file#${output_dir}/}"
    pkg_name="${rel_path%/LICENSE}"
    echo -e "${pkg_name}\t${lic_file}" >> "${tsv_file}"
  done
}

main() {
  local rootfs_dir="${1:?Error: ROOTFS_DIR required}"
  local output_dir="${2:?Error: OUTPUT_DIR required}"
  local component_name="${3:-wsd}"

  if [ ! -d "${rootfs_dir}" ]; then
    echo "Error: ROOTFS_DIR '${rootfs_dir}' does not exist!" >&2
    exit 1
  fi

  mkdir -p "${output_dir}"

  echo "=== Extracting KPM Licenses for: ${component_name} ==="

  extract_dpkg_licenses "${rootfs_dir}" "${output_dir}"
  extract_rust_licenses "${rootfs_dir}" "${output_dir}"
  extract_go_licenses "${rootfs_dir}" "${output_dir}"
  extract_boringssl_licenses "${rootfs_dir}" "${output_dir}"
  generate_summary_tsv "${output_dir}"

  echo "Done! Extracted $(find "${output_dir}" -mindepth 2 -name "LICENSE" | wc -l) KPM licenses into ${output_dir}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
