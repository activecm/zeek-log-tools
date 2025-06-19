#!/bin/bash
#V0.4
#Extracts lines of interest from zeek logs in the current directory.
#

#Assumes that the logs to read are in the current directory.

#======== Support functions
require_util () {
	#Returns true if all binaries listed as parameters exist somewhere in the path, False if one or more missing.
        while [ -n "$1" ]; do
                if ! type -path "$1" >/dev/null 2>/dev/null ; then
                        echo Missing utility "$1". Please install it. >&2
                        return 1        #False, app is not available.
                fi
                shift
        done
        return 0        #True, app is there.
} #End of requireutil


usage () {
	echo "extract-from-zeek.sh" >&2
	echo "Reads logs from the current directory.  Log lines that have the specified search term(s)" >&2
	echo "are written to the output directory." >&2
	echo "Usage:" >&2
	echo "$0 output_log_directory search_string optional_second_search optional_third_search optional_fourth_search" >&2
	echo "Examples:" >&2
	echo "$0 $HOME/filtered/ [[:space:]]8\.8\.8\.8[[:space:]]" >&2
	echo "$0 $HOME/filtered/ [[:space:]]8\.8\.8\.8[[:space:]] udp dns [[:space:]]53[[:space:]]" >&2
	exit 1
} #End of usage

fail () {
	echo "$1 , exiting." >&2
	exit 1
} #End of fail


#======== Read command line parameters.  Some may be blank, but that's fine; we test for that below.
if [ "z$1" = "z-h" ] || [ "z$1" = "z-help" ] || [ "z$1" = "z/h" ] ; then
	usage
elif [ -z "$1" ] || [ -z "$2" ]; then
	usage
else
	out_dir="$1"
	search_string="$2"
	second_search_string="$3"
	third_search_string="$4"
	fourth_search_string="$5"
fi

#======== Checks before starting
#Check that we have basic tools to continue
require_util cat grep gzip mkdir nice rm wc		|| fail "Missing a required utility"
if type -path zcutter >/dev/null 2>&1 ; then
	zc_bin="zcutter"
elif type -path zcutter.py >/dev/null 2>&1 ; then
	zc_bin="zcutter.py"
else
	fail "Unable to locate either zcutter or zcutter.py in your path - please see https://github.com/activecm/zcutter/?tab=readme-ov-file#quickstart"
fi

#======== Main
mkdir -p "$out_dir" || fail "Unable to create directory"

for one_log in *.log.gz ; do
	#Read "$one_log", copying the original file to "$HOME/filtered/"
	$zc_bin -C -t -r "$one_log" \
| grep -E '(^#|'"$search_string"')' \
| if [ -n "$second_search_string" ]; then grep -E '(^#|'"$second_search_string"')' ; else cat ; fi \
| if [ -n "$third_search_string" ]; then grep -E '(^#|'"$third_search_string"')' ; else cat ; fi \
| if [ -n "$fourth_search_string" ]; then grep -E '(^#|'"$fourth_search_string"')' ; else cat ; fi \
>"$out_dir/${one_log%.gz}"

	#Following block will remove any output files that _only_ contain headers+footers (that all start with "#")
	if [ `cat "$out_dir/${one_log%.gz}" | grep -v '^#' | wc -l` -eq 0 ]; then
		rm -f "$out_dir/${one_log%.gz}"
	fi
done

echo "If you would like the output logs to be compressed, please run this command:" >&2
echo "cd $out_dir && nice gzip -9 *.log" >&2
