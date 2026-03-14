#!/bin/bash
# Program to build and sign debian packages, and upload those to a public reprepro repository.
# Copyright (c) 2015 Santiago Bassett <santiago.bassett@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

#
# CONFIGURATION VARIABLES
#

NAME="ossec-hids"
ossec_version='4.0.0'
source_file="${NAME}-${ossec_version}.tar.gz"
#packages=(ossec-hids ossec-hids-agent) # only options available
packages=(ossec-hids ossec-hids-agent)

# codenames=(sid jessie wheezy precise trusty utopic)
codenames=(bookworm)

# For Debian use: sid, jessie, wheezy, bookworm (hardcoded in update_changelog function)
# For Ubuntu use: xenial, bionic, focal, jammy, noble (24.04)
codenames_ubuntu=(xenial bionic focal jammy noble)
codenames_debian=(sid jessie wheezy bookworm)

# architectures=(amd64 i386) only options available
architectures=(amd64)

# Debian files path (set after scriptpath below; use contrib/debian-packages, no version subdir)
debian_files_path=""

# Setting up paths
scriptpath=$( cd $(dirname $0) ; pwd -P )
debian_files_path="${scriptpath}"
repo_root="$(cd "${scriptpath}/../.." && pwd)"
build_root="${scriptpath}/build"
logfile=$scriptpath/ossec_packages.log

# Optional env overrides for one-off tests (e.g. on Fedora: CODENAMES=noble ARCHITECTURES=amd64)
[[ -n "${CODENAMES:-}" ]]    && codenames=(${CODENAMES})
[[ -n "${ARCHITECTURES:-}" ]] && architectures=(${ARCHITECTURES})


#
# Function to write to LOG_FILE
#
write_log() 
{
  if [ ! -e "$logfile" ] ; then
    touch "$logfile"
  fi
  while read text
  do 
      local logtime=`date "+%Y-%m-%d %H:%M:%S"`
      echo $logtime": $text" | tee -a $logfile;
  done
}


#
# Check if element is in an array
# Arguments: element array
#
contains_element() {
  local e
  for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 0; done
  return 1
}


#
# Show help function
#
show_help()
{ 
  echo "
  This tool builds OSSEC Debian/Ubuntu packages with pbuilder.

  CONFIGURATION: The script is currently configured with the following variables:
    * Packages: ${packages[*]}. 
    * Distributions: ${codenames[*]}. 
    * Architectures: ${architectures[*]}.
    * OSSEC version: ${ossec_version}.
    * Source file: ${source_file}.
    * Signing key: ${signing_key}.

  USAGE: Command line arguments available:
    -h | --help     Displays this help.
    -u | --update   Updates chroot environments.
    -d | --download Downloads source file and prepares source directories.
    -b | --build    Builds deb packages.
    -s | --sync     Synchronizes with the apt-get repository.
  "
}


#
# Reads latest package version from changelog file
# Argument: changelog_file
#
read_package_version()
{
  if [ ! -e "$1" ] ; then
    echo "Error: Changelog file $1 does not exist" | write_log
    exit 1
  fi
  local regex="^ossec-hids[A-Za-z-]* \([0-9]+.*[0-9]*.*[0-9]*-([0-9]+)[A-Za-z]*\)"
  while read line
  do
    if [[ $line =~ $regex ]]; then
      package_version="${BASH_REMATCH[1]}"
      break
    fi
  done < $1
  local check_regex='^[0-9]+$'
  if ! [[ ${package_version} =~ ${check_regex} ]]; then
    echo "Error: Package version could not be read from $1" | write_log
    exit 1
  fi
}


#
# Updates changelog file with new codename, date and debdist.
# Arguments: changelog_file codename
#
update_changelog()
{
  local changelog_file=$1
  local changelog_file_tmp="${changelog_file}.tmp"
  local codename=$2

  if [ ! -e "$1" ] ; then
    echo "Error: Changelog file $1 does not exist" | write_log
    exit 1
  fi

  local check_codenames=( ${codenames_debian[*]} ${codenames_ubuntu[*]} )
  if ! contains_element $codename ${check_codenames[*]} ; then
    echo "Error: Codename $codename not contained in codenames for Debian or Ubuntu" | write_log
    exit 1
  fi

  # For Debian
  if [ $codename = "sid" ]; then
    local debdist="unstable"
  elif [ $codename = "jessie" ]; then
    local debdist="testing"
  elif [ $codename = "wheezy" ]; then
    local debdist="stable"
  elif [ $codename = "bookworm" ]; then
    local debdist="bookworm"
  fi

  # For Ubuntu
  if contains_element $codename ${codenames_ubuntu[*]} ; then
    local debdist=$codename
  fi
  
  # Modifying file
  local changelogtime=$(date -R)
  local last_date_changed=0

  local regex1="^(ossec-hids[A-Za-z-]* \([0-9]+.*[0-9]*.*[0-9]*-[0-9]+)[A-Za-z]*\)"
  local regex2="( -- [[:alnum:]]*[^>]*>  )[[:alnum:]]*,"

  if [ -f ${changelog_file_tmp} ]; then
    rm -f ${changelog_file_tmp}
  fi
  touch ${changelog_file_tmp}

  IFS='' #To preserve line leading whitespaces
  while read line
  do
    if [[ $line =~ $regex1 ]]; then
      line="${BASH_REMATCH[1]}$codename) $debdist; urgency=low"
    fi
    if [[ $line =~ $regex2 ]] && [ $last_date_changed -eq 0 ]; then
      line="${BASH_REMATCH[1]}$changelogtime"
      last_date_changed=1
    fi
    echo "$line" >> ${changelog_file_tmp}
  done < ${changelog_file}

  mv ${changelog_file_tmp} ${changelog_file}
}


#
# Update chroot environments
#
update_chroots()
{
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do
      # Ensure pbuilder cache dirs exist (debootstrap fails if aptcache/ is missing)
      sudo mkdir -p /var/cache/pbuilder/${codename}-${arch}/aptcache \
                    /var/cache/pbuilder/${codename}-${arch}/result \
                    /var/cache/pbuilder/build
      if [ -f /var/cache/pbuilder/$codename-$arch-base.tgz ]; then
        echo "Updating chroot environment: ${codename}-${arch}" | write_log
        if sudo DIST=$codename ARCH=$arch pbuilder update --configfile $scriptpath/pbuilderrc ; then
          echo "Successfully updated chroot environment: ${codename}-${arch}" | write_log
        else
          echo "Error: Problem detected updating chroot environment: ${codename}-${arch}" | write_log
          exit 1
        fi
      else
        echo "Creating chroot environment: ${codename}-${arch}" | write_log
        if sudo DIST=$codename ARCH=$arch pbuilder create --configfile $scriptpath/pbuilderrc; then
          echo "Successfully created chroot environment: ${codename}-${arch}" | write_log
        else
          echo "Error: Problem detected creating chroot environment: ${codename}-${arch}" | write_log
          exit 1
        fi
      fi
    done
  done
}


#
# Prepare source directories for building. Uses a dedicated build/ dir so we never
# overwrite the packaging dirs (contrib/debian-packages/ossec-hids, ossec-hids-agent).
# Prefer building from the local tree when possible (repo with .git and src/).
#
download_source()
{
  # Check that Debian packaging dirs exist (we only read from them)
  for package in ${packages[*]}; do
    if [ ! -d "${debian_files_path}/$package/debian" ]; then
      echo "Error: Couldn't find debian files directory for $package at ${debian_files_path}/$package/debian" | write_log
      exit 1
    fi
  done

  mkdir -p "${build_root}"
  cd "${build_root}"
  tmp_directory="${NAME}-${ossec_version}"

  # Prefer local tree when we have a full repo (src/ present)
  if [ -d "${repo_root}/src" ]; then
    echo "Building from local source tree at ${repo_root}" | write_log
    if [ -f "${build_root}/${source_file}" ]; then
      rm -f "${build_root}/${source_file}"
    fi
    (cd "${repo_root}" && tar -czf "${build_root}/${source_file}" --exclude='.git' --exclude="${source_file}" \
      --transform "s,^\./,${tmp_directory}/," .)
  else
    # Download or use SOURCE_TARBALL
    if [ -n "${SOURCE_TARBALL:-}" ] && [ -f "${SOURCE_TARBALL}" ]; then
      cp -p "${SOURCE_TARBALL}" "${build_root}/${source_file}"
      echo "Using local source tarball ${SOURCE_TARBALL}" | write_log
    elif wget -O "${build_root}/${source_file}" -U ossec "https://github.com/ossec/ossec-hids/archive/${ossec_version}.tar.gz"; then
      echo "Successfully downloaded ${source_file} from GitHub" | write_log
    else
      echo "Error: Could not obtain ${source_file}. Set SOURCE_TARBALL or run from a git clone." | write_log
      exit 1
    fi
  fi

  # Unpack and prepare each package under build/ (never touch scriptpath/package)
  for package in ${packages[*]}; do
    rm -rf "${build_root}/${package}"
    mkdir -p "${build_root}/${package}"
    tar -xzf "${build_root}/${source_file}" -C "${build_root}/${package}"
    if [ ! -d "${build_root}/${package}/${tmp_directory}" ]; then
      echo "Error: Unpack did not create ${build_root}/${package}/${tmp_directory}" | write_log
      exit 1
    fi
    target="${build_root}/${package}/${package}-${ossec_version}"
    if [ "${build_root}/${package}/${tmp_directory}" != "${target}" ]; then
      mv "${build_root}/${package}/${tmp_directory}" "${target}"
    fi
    cp -p "${build_root}/${source_file}" "${build_root}/${package}/${package}_${ossec_version}.orig.tar.gz"
    cp -pr "${debian_files_path}/${package}/debian" "${target}/debian"
  done

  echo "Prepared source for ${packages[*]} version ${ossec_version} under ${build_root}" | write_log
}


#
# Build packages
#
build_packages()
{

for package in ${packages[@]}
do 
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do

      echo "Building Debian package ${package} ${codename}-${arch}" | write_log

      # Prefer build/ (local or prepared source); fall back to scriptpath/package for backward compat
      local source_path=""
      if [ -f "${build_root}/${package}/${package}-${ossec_version}/debian/changelog" ]; then
        source_path="${build_root}/${package}/${package}-${ossec_version}"
      elif [ -f "$scriptpath/${package}/${package}-${ossec_version}/debian/changelog" ]; then
        source_path="$scriptpath/${package}/${package}-${ossec_version}"
      fi
      if [ -z "${source_path}" ] || [ ! -f "${source_path}/debian/changelog" ]; then
        echo "Error: Couldn't find changelog for ${package}-${ossec_version}. Run -d first to prepare source." | write_log
        exit 1
      fi
      local changelog_file="${source_path}/debian/changelog"
      
      # Updating changelog file with new codename, date and debdist.
      if update_changelog ${changelog_file} ${codename} ; then
        echo " + Changelog file ${changelog_file} updated for $package ${codename}-${arch}" | write_log
      else
        echo "Error: Changelog file ${changelog_file} for $package ${codename}-${arch} could not be updated" | write_log
        exit 1
      fi

      # Setting up global variable package_version, used for deb_file and changes_file
      read_package_version ${changelog_file}      
      local deb_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.deb"
      local changes_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.changes"
      local dsc_file="${package}_${ossec_version}-${package_version}${codename}.dsc"
      local results_dir="/var/cache/pbuilder/${codename}-${arch}/result/${package}"
      local base_tgz="/var/cache/pbuilder/${codename}-${arch}-base.tgz"
      local cache_dir="/var/cache/pbuilder/${codename}-${arch}/aptcache"

      # Creating results directory if it does not exist
      if [ ! -d ${results_dir} ]; then
        sudo mkdir -p ${results_dir}
      fi

      # Building the package (configfile must be absolute so it works from any cwd)
      local build_log="${build_root}/pdebuild-${package}-${codename}-${arch}.log"
      cd ${source_path}
      if sudo DIST=$codename ARCH=$arch /usr/bin/pdebuild --configfile "$scriptpath/pbuilderrc" --use-pdebuild-internal --architecture ${arch} --buildresult ${results_dir} -- --basetgz \
      ${base_tgz} --distribution ${codename} --architecture ${arch} --aptcache ${cache_dir} --override-config >> "${build_log}" 2>&1 ; then
        echo " + Successfully built Debian package ${package} ${codename}-${arch}" | write_log
      else
        echo "Error: Could not build package $package ${codename}-${arch}" | write_log
        echo "Last 100 lines of build log (full log: ${build_log}):" | write_log
        tail -100 "${build_log}" | while read line; do echo "$line" | write_log; done
        echo "---" | write_log
        echo "Build failed. Last 100 lines of build output:" 1>&2
        tail -100 "${build_log}" 1>&2
        exit 1
      fi

      # Checking that resulting debian package exists
      if [ ! -f ${results_dir}/${deb_file} ] ; then
        echo "Error: Could not find ${results_dir}/${deb_file}" | write_log
        exit 1
      fi
      
      # Checking that package has at least 50 files to confirm it has been built correctly
      local files=$(sudo /usr/bin/dpkg --contents ${results_dir}/${deb_file} | wc -l)
      if [ "${files}" -lt "50" ]; then
        echo "Error: Package ${package} ${codename}-${arch} contains only ${files} files" | write_log
        echo "Error: Check that the Debian package has been built correctly" | write_log
        exit 1
      else
        echo " + Package ${results_dir}/${deb_file} ${codename}-${arch} contains ${files} files" | write_log
      fi

      # Copy built artifacts into repo for easy access (build/result/<codename>-<arch>/)
      local out_dir="${build_root}/result/${codename}-${arch}"
      mkdir -p "${out_dir}"
      sudo cp -p "${results_dir}/${deb_file}" "${results_dir}/${changes_file}" "${out_dir}/" 2>/dev/null || true
      sudo cp -p "${results_dir}"/*.buildinfo "${out_dir}/" 2>/dev/null || true
      sudo chown "$(id -un):$(id -gn)" "${out_dir}"/* 2>/dev/null || true

      echo "Successfully built Debian package ${package} ${codename}-${arch}" | write_log

    done
  done
done
  echo "Built .deb and .changes are in ${build_root}/result/<codename>-<arch>/ and in /var/cache/pbuilder/<codename>-<arch>/result/<package>/" | write_log
}

# Synchronizes with the external repository, uploading new packages and ubstituting old ones.
sync_repository()
{
for package in ${packages[@]}
do
  for codename in ${codenames[@]}
  do
    for arch in ${architectures[@]}
    do

      # Reading package version from changelog file
      local source_path="$scriptpath/${package}/${package}-${ossec_version}"
      local changelog_file="${source_path}/debian/changelog"
      if [ ! -f ${changelog_file} ] ; then
        echo "Error: Couldn't find ${changelog_file} for package ${package} ${codename}-${arch}" | write_log
        exit 1
      fi

      # Setting up global variable package_version, used for deb_file and changes_file.
      read_package_version ${changelog_file}
      local deb_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.deb"
      local changes_file="${package}_${ossec_version}-${package_version}${codename}_${arch}.changes"
      local results_dir="/var/cache/pbuilder/${codename}-${arch}/result/${package}"
      if [ ! -f ${results_dir}/${deb_file} ] || [ ! -f ${results_dir}/${changes_file} ] ; then
        echo "Error: Couldn't find ${deb_file} or ${changes_file}" | write_log
        exit 1
      fi

      # Uploading package to repository
      cd ${results_dir}
      echo "Uploading package ${changes_file} for ${codename} to OSSEC repository" | write_log
      if sudo /usr/bin/dupload --nomail -f --to ossec-repository ${changes_file} ; then
        echo " + Successfully uploaded package ${changes_file} for ${codename} to OSSEC repository" | write_log
      else
        echo "Error: Could not upload package ${changes_file} for ${codename} to the repository" | write_log
        exit 1
      fi 

      # Checking if it is an Ubuntu package
      if contains_element $codename ${codenames_ubuntu[*]} ; then
        local is_ubuntu=1
      else
        local is_ubuntu=0
      fi

      # Moving package to the right directory at the OSSEC apt repository server
      echo " + Adding package /opt/incoming/${deb_file} to server repository for ${codename} distribution" | write_log
      if [ $is_ubuntu -eq 1 ]; then 
        remove_package="cd /var/www/repos/apt/ubuntu; reprepro -A ${arch} remove ${codename} ${package}"
        include_package="cd /var/www/repos/apt/ubuntu; reprepro includedeb ${codename} /opt/incoming/${deb_file}"
      else
        remove_package="cd /var/www/repos/apt/debian; reprepro -A ${arch} remove ${codename} ${package}"
        include_package="cd /var/www/repos/apt/debian; reprepro includedeb ${codename} /opt/incoming/${deb_file}"
      fi

      echo "Successfully added package ${deb_file} to server repository for ${codename} distribution" | write_log
    done
  done
done
}


# If there are no arguments, display help
if [ $# -eq 0 ]; then
  show_help
  exit 0
fi

# Reading command line arguments
while [[ $# > 0 ]]
do
key="$1"
shift

case $key in
  -h|--help)
    show_help
    exit 0
    ;;
  -u|--update)
    update_chroots
    shift
    exit 0
    ;;
  -d|--download)
    download_source
    shift
    exit 0
    ;;
  -b|--build)
    build_packages
    shift
    exit 0
    ;;
  -s|--sync)
    sync_repository
    shift
    ;;
  *)
    echo "Unknown command line argument."
    show_help
    exit 0
    ;;
  esac
done

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2
